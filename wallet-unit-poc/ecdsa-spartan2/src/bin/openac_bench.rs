//! Mac benchmark harness. `run` repeats the `mobile/src/flow.rs` Prepare, Present and Verify calls
//! with the same step boundaries and writes schema-2 JSONL rows; `generic` proves any r1cs + wtns.
//! Subcommands: run, present, emit-expected, shape, digest, generic {setup, run}.

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::reader::load_r1cs;
use ecdsa_spartan2::{
    circuits::{bind_shared, synthesize_all_vars, synthesize_witness_only},
    generate_prepare_witness, load_proving_key, load_verifying_key, parse_witness,
    prove_circuit_in_memory, reblind_in_memory, save_keys, CircuitSize, PathConfig,
    PrepareCircuit, Scalar, ShowCircuit, E,
};
use ff::{Field, PrimeField};
use num_bigint::{BigInt, Sign};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use spartan2::{
    r1cs::{R1CSWitness, SplitR1CSInstance},
    traits::{circuit::SpartanCircuit, snark::{DigestHelperTrait, R1CSSNARKTrait}},
    zk_spartan::R1CSSNARK,
};
use std::{
    any::type_name,
    collections::HashMap,
    fs::{self, File},
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

type PK = <R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey;
type VK = <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey;
type Res<T> = Result<T, String>;

const BOOL_FLAGS: &[&str] = &["no-check", "r1cs-present", "save-state", "save-presentation", "smoke"];

/// Set by `--smoke`: every row written carries `smoke: true`.
static SMOKE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

struct Opts(HashMap<String, String>);

impl Opts {
    fn parse(args: &[String]) -> Opts {
        let mut m = HashMap::new();
        let mut i = 0;
        while i < args.len() {
            let key = args[i].trim_start_matches("--").to_string();
            if BOOL_FLAGS.contains(&key.as_str()) {
                m.insert(key, "1".into());
                i += 1;
            } else {
                m.insert(key, args.get(i + 1).cloned().unwrap_or_default());
                i += 2;
            }
        }
        Opts(m)
    }
    fn get(&self, k: &str) -> Option<&str> {
        self.0.get(k).map(String::as_str)
    }
    fn req(&self, k: &str) -> &str {
        self.get(k).unwrap_or_else(|| die(&format!("missing --{k}")))
    }
    fn num(&self, k: &str, default: usize) -> usize {
        self.get(k).map_or(default, |v| v.parse().unwrap_or_else(|_| die(&format!("bad --{k}"))))
    }
    fn flag(&self, k: &str) -> bool {
        self.0.contains_key(k)
    }
}

fn die(msg: &str) -> ! {
    eprintln!("openac_bench: {msg}");
    std::process::exit(2)
}

fn ok_or_die<T>(r: Res<T>) -> T {
    r.unwrap_or_else(|e| die(&e))
}

fn threads() -> usize {
    std::env::var("RAYON_NUM_THREADS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()))
}

fn now_s() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn sysctl(key: &str) -> String {
    Command::new("sysctl")
        .args(["-n", key])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn timed<T>(f: impl FnOnce() -> T) -> (T, u128) {
    let t = Instant::now();
    let v = f();
    (v, t.elapsed().as_micros())
}

/// macOS thermal pressure level (0 nominal); null when it cannot be read.
fn thermal_pressure() -> Option<u64> {
    let out = Command::new("notifyutil").args(["-g", "com.apple.system.thermalpressurelevel"]).output().ok()?;
    String::from_utf8_lossy(&out.stdout).split_whitespace().last()?.parse().ok()
}

fn sha_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

fn fingerprint(bytes: &[u8]) -> String {
    sha_hex(bytes)[..16].to_string()
}

fn file_sha(path: &Path) -> Res<String> {
    let mut f = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut h).map_err(|e| e.to_string())?;
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn decimal(s: &Scalar) -> String {
    BigInt::from_bytes_le(Sign::Plus, s.to_repr().as_ref()).to_string()
}

fn decimals(v: &[Scalar]) -> Vec<String> {
    v.iter().map(decimal).collect()
}

fn ser<T: serde::Serialize>(v: &T, what: &str) -> Res<Vec<u8>> {
    bincode::serialize(v).map_err(|e| format!("serialize {what}: {e}"))
}

fn load_bin<T: serde::de::DeserializeOwned>(path: &Path) -> Res<T> {
    let f = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    bincode::deserialize_from(BufReader::new(f)).map_err(|e| format!("{}: {e}", path.display()))
}

fn save_bin(path: &Path, bytes: &[u8]) -> Res<()> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    fs::write(path, bytes).map_err(|e| format!("{}: {e}", path.display()))
}

fn read_json(path: &Path) -> Res<Value> {
    let b = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", path.display()))
}

/// Row writer; `ctx` fields (cell, config, ...) are copied onto every ITER row.
struct Out {
    file: BufWriter<File>,
    ctx: Map<String, Value>,
    nthreads: usize,
}

impl Out {
    fn open(path: &str, ctx: Map<String, Value>) -> Out {
        if let Some(p) = Path::new(path).parent() {
            let _ = fs::create_dir_all(p);
        }
        let f = fs::OpenOptions::new().create(true).append(true).open(path).unwrap_or_else(|e| die(&format!("{path}: {e}")));
        Out { file: BufWriter::new(f), ctx, nthreads: threads() }
    }
    fn row(&mut self, mut v: Value) {
        if SMOKE.load(std::sync::atomic::Ordering::Relaxed) {
            v["smoke"] = true.into();
        }
        writeln!(self.file, "{v}").and_then(|_| self.file.flush()).unwrap_or_else(|e| die(&format!("writing rows: {e}")));
    }
    fn iter(&self, step: &str, us: u128, phase: &str, iter: usize, flow: Value) -> Value {
        let mut m = Map::new();
        m.insert("kind".into(), "ITER".into());
        m.insert("step".into(), step.into());
        m.insert("wall_us".into(), (us as u64).into());
        m.insert("phase".into(), phase.into());
        m.insert("iter".into(), iter.into());
        m.insert("threads".into(), self.nthreads.into());
        m.insert("flow".into(), flow);
        for k in ["cell", "config", "matrix_id"] {
            if let Some(v) = self.ctx.get(k) {
                m.insert(k.into(), v.clone());
            }
        }
        Value::Object(m)
    }
    /// Writes one iteration's rows with a common `ok` (null when nothing was verified).
    fn flush(&mut self, rows: Vec<Value>, ok: Option<bool>) {
        for mut r in rows {
            r["ok"] = json!(ok);
            self.row(r);
        }
    }
}

fn device_row(o: &Opts, extra: &Map<String, Value>) -> Map<String, Value> {
    let mut m = Map::new();
    let mem_kb = sysctl("hw.memsize").parse::<u64>().unwrap_or(0) / 1024;
    for (k, v) in [
        ("kind", json!("DEVICE")),
        ("platform", json!("macos")),
        ("product_model", json!(sysctl("hw.model"))),
        ("soc_model", json!(sysctl("machdep.cpu.brand_string"))),
        ("cpu_count", json!(sysctl("hw.ncpu").parse::<u64>().unwrap_or(0))),
        ("mem_total_kb", json!(mem_kb)),
        ("rayon_default_threads", json!(std::thread::available_parallelism().map_or(1, |n| n.get()))),
        ("threads_requested", json!(std::env::var("RAYON_NUM_THREADS").ok())),
        ("schema", json!(2)),
        ("harness", json!("openac_bench")),
        ("run_id", json!(o.get("run-id").unwrap_or("adhoc"))),
        ("r1cs_present", json!(o.flag("r1cs-present"))),
        ("ts", json!(now_s())),
        ("vk_digest", json!("computed")),
        ("page_cache", json!("warm")),
        ("thermal_pressure", json!(thermal_pressure())),
        ("command", json!(std::env::args().collect::<Vec<_>>().join(" "))),
        ("batch", json!(o.num("batch", 0))),
    ] {
        m.insert(k.into(), v);
    }
    for (k, v) in extra {
        m.insert(k.clone(), v.clone());
    }
    if let Some(sha) = extra.get("bench_sha") {
        m.insert("commit".into(), sha.clone());
    }
    m
}

fn context(o: &Opts) -> (Map<String, Value>, Map<String, Value>) {
    let mut meta = Map::new();
    if let Some(dir) = o.get("dir") {
        if let Ok(Value::Object(m)) = read_json(&Path::new(dir).join("meta.json")) {
            meta = m;
        }
    }
    if let Some(x) = o.get("extra") {
        if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(x) {
            meta.extend(m);
        }
    }
    let ctx: Map<String, Value> = ["cell", "config", "matrix_id"]
        .iter()
        .filter_map(|k| meta.get(*k).map(|v| (k.to_string(), v.clone())))
        .collect();
    (ctx, meta)
}

// ---------- verification helpers ----------

/// Deserializes both verifying keys from storage.
fn load_vks(config: &PathConfig) -> Res<(VK, VK)> {
    let load = |name: &str, what: &str| -> Res<VK> {
        load_verifying_key(config.key_path(name)).map_err(|e| format!("{what} vk: {e}"))
    };
    Ok((load("prepare_verifying.key", "prepare")?, load("show_verifying.key", "show")?))
}

/// Forces the vk digests, which are otherwise computed on first use; the phone build restores them from a sidecar.
fn force_digests(vks: &[&VK]) -> Res<()> {
    for vk in vks {
        vk.digest().map_err(|e| format!("vk digest: {e:?}"))?;
    }
    Ok(())
}

fn comm_shared_eq(a: &R1CSSNARK<E>, b: &R1CSSNARK<E>) -> bool {
    let (x, y) = (a.comm_W_shared(), b.comm_W_shared());
    x.is_some() && y.is_some() && x == y
}

/// Both proofs verify and commit to the same shared witness. Returns the public values.
fn verify_linked(pp: &R1CSSNARK<E>, pvk: &VK, sp: &R1CSSNARK<E>, svk: &VK) -> Option<(Vec<Scalar>, Vec<Scalar>)> {
    let ppv = pp.verify(pvk).ok()?;
    let spv = sp.verify(svk).ok()?;
    comm_shared_eq(pp, sp).then_some((ppv, spv))
}

struct Expected {
    prepare: Vec<String>,
    show: Vec<String>,
}

fn load_expected(dir: &Path) -> Res<Option<Expected>> {
    let p = dir.join("docs/expected.json");
    if !p.exists() {
        return Ok(None);
    }
    let v = read_json(&p)?;
    let list = |k: &str| -> Res<Vec<String>> {
        v[k].as_array()
            .ok_or_else(|| format!("expected.json: {k} missing"))?
            .iter()
            .map(|x| x.as_str().map(String::from).ok_or_else(|| format!("expected.json: {k} entry")))
            .collect()
    };
    Ok(Some(Expected { prepare: list("prepare_public")?, show: list("show_public")? }))
}

// ---------- product path ----------

struct PrepareState {
    instance: SplitR1CSInstance<E>,
    witness: R1CSWitness<E>,
}

struct Ctx<'a> {
    config: PathConfig,
    dir: PathBuf,
    jwt_input: PathBuf,
    show_input: PathBuf,
    expected: Option<Expected>,
    batch: usize,
    out: &'a mut Out,
}

fn prepare_step(c: &Ctx, pk: &PK, iter: usize, phase: &str, rows: &mut Vec<Value>) -> Res<(PrepareState, R1CSSNARK<E>)> {
    let (witness, w_us) = timed(|| generate_prepare_witness(&c.config, Some(&c.jwt_input)));
    let witness = witness.map_err(|e| format!("prepare witness: {e:?}"))?;
    // Circuit construction counts as prove time, as in flow.rs.
    let (res, p_us) = timed(|| {
        let circuit = PrepareCircuit::with_witness_for_size(witness, c.config.circuit_size);
        prove_circuit_in_memory(circuit, pk)
    });
    let (proof, instance, witness) = res.map_err(|e| format!("prepare prove: {e:?}"))?;
    let proof_bytes = ser(&proof, "prepare proof")?;
    let flow = json!({
        "witness_ms": w_us / 1000, "prove_ms": p_us / 1000,
        "proof_bytes": proof_bytes.len(), "instance_bytes": ser(&instance, "prepare instance")?.len(),
        "proof_fingerprint": fingerprint(&proof_bytes),
    });
    rows.push(c.out.iter("prepare_witness", w_us, phase, iter, flow.clone()));
    rows.push(c.out.iter("prepare_prove", p_us, phase, iter, flow.clone()));
    rows.push(c.out.iter("prepare_total", w_us + p_us, phase, iter, flow));
    Ok((PrepareState { instance, witness }, proof))
}

struct Presented {
    prepare_proof: Vec<u8>,
    show_proof: Vec<u8>,
    prepare_pv: Vec<Scalar>,
    show_pv: Vec<Scalar>,
    state_bytes: Value,
}

fn present_step(c: &Ctx, ppk: &PK, spk: &PK, st: &PrepareState, iter: usize, phase: &str, rows: &mut Vec<Value>) -> Res<Presented> {
    let total = Instant::now();
    let t = Instant::now();
    let circuit = ShowCircuit::new(c.config.clone(), Some(c.show_input.clone()));
    // Filling the circuit's cached witness first separates Show witness generation from the prove proper.
    let (witness_ok, show_witness_us) = timed(|| SpartanCircuit::<E>::public_values(&circuit));
    witness_ok.map_err(|e| format!("show witness: {e:?}"))?;
    let (proved, show_prove_only_us) = timed(|| prove_circuit_in_memory(circuit, spk));
    let (_, show_instance, show_witness) = proved.map_err(|e| format!("show prove: {e:?}"))?;
    let show_prove_us = t.elapsed().as_micros();

    let shared_rows = st.instance.num_shared_rows();
    if show_instance.num_shared_rows() != shared_rows {
        return Err(format!("prepare has {shared_rows} shared rows but show has {}", show_instance.num_shared_rows()));
    }
    let blinds: Vec<Scalar> = (0..shared_rows).map(|_| Scalar::random(&mut ff::derive::rand_core::OsRng)).collect();

    let t = Instant::now();
    let (pp, p_inst, _) = reblind_in_memory(ppk, st.instance.clone(), st.witness.clone(), &blinds).map_err(|e| format!("prepare reblind: {e:?}"))?;
    let prepare_reblind_us = t.elapsed().as_micros();

    let t = Instant::now();
    let (sp, s_inst, _) = reblind_in_memory(spk, show_instance, show_witness, &blinds).map_err(|e| format!("show reblind: {e:?}"))?;
    let show_reblind_us = t.elapsed().as_micros();

    let prepare_proof = ser(&pp, "prepare proof")?;
    let show_proof = ser(&sp, "show proof")?;
    let total_us = total.elapsed().as_micros();
    let match_ = p_inst.comm_W_shared.is_some() && s_inst.comm_W_shared.is_some() && comm_shared_eq(&pp, &sp);
    let prepare_pv = p_inst.get_public_values().to_vec();
    let show_pv = s_inst.get_public_values().to_vec();
    let flow = json!({
        "prepare_fingerprint": fingerprint(&prepare_proof), "show_fingerprint": fingerprint(&show_proof),
        "prepare_proof_bytes": prepare_proof.len(), "show_proof_bytes": show_proof.len(),
        "show_prove_ms": show_prove_us / 1000, "show_witness_ms": show_witness_us / 1000, "show_prove_only_ms": show_prove_only_us / 1000, "prepare_reblind_ms": prepare_reblind_us / 1000,
        "show_reblind_ms": show_reblind_us / 1000, "total_ms": total_us / 1000, "comm_w_shared_match": match_,
    });
    for (s, us) in [("show_witness", show_witness_us), ("show_prove_only", show_prove_only_us), ("show_prove", show_prove_us), ("prepare_reblind", prepare_reblind_us), ("show_reblind", show_reblind_us), ("present_total", total_us)] {
        rows.push(c.out.iter(s, us, phase, iter, flow.clone()));
    }

    if c.batch > 0 {
        // One tuple is a reblinded Prepare proof plus its blinds; serialization is in memory and inside the timer.
        let t = Instant::now();
        let mut tuple_bytes = 0;
        for _ in 0..c.batch {
            let b: Vec<Scalar> = (0..shared_rows).map(|_| Scalar::random(&mut ff::derive::rand_core::OsRng)).collect();
            let (proof, _, _) = reblind_in_memory(ppk, st.instance.clone(), st.witness.clone(), &b).map_err(|e| format!("batch prepare reblind: {e:?}"))?;
            tuple_bytes = ser(&proof, "batch proof")?.len() + ser(&b, "batch blinds")?.len();
        }
        let mut row = c.out.iter("batch_reblind", t.elapsed().as_micros(), phase, iter, json!({"bytes_per_tuple": tuple_bytes}));
        row["batch"] = json!(c.batch);
        rows.push(row);
    }

    let blinds_bytes = ser(&blinds, "blinds")?.len();
    let state_bytes = json!({
        "instance": ser(&st.instance, "instance")?.len(), "witness": ser(&st.witness, "witness")?.len(), "blinds": blinds_bytes,
    });
    if !match_ {
        return Err("prepare and show commitments to the shared witness differ".into());
    }
    Ok(Presented { prepare_proof, show_proof, prepare_pv, show_pv, state_bytes })
}

fn statement_matches(e: &Expected, prepare_pv: &[Scalar], show_pv: &[Scalar]) -> bool {
    decimals(prepare_pv) == e.prepare && decimals(show_pv) == e.show
}

/// `vk_load`, `vk_digest`, `verify` and `statement_check` rows plus their `verify_total`; returns whether everything held.
/// `verify` is verification only, with the vks already in memory.
fn verify_step(c: &Ctx, pp: &[u8], sp: &[u8], iter: usize, phase: &str, rows: &mut Vec<Value>) -> Res<bool> {
    let total = Instant::now();
    let t = Instant::now();
    let (pvk, svk) = load_vks(&c.config)?;
    let vk_us = t.elapsed().as_micros();
    let t = Instant::now();
    force_digests(&[&pvk, &svk])?;
    let digest_us = t.elapsed().as_micros();

    let t = Instant::now();
    let (Ok(pp), Ok(sp)) = (bincode::deserialize::<R1CSSNARK<E>>(pp), bincode::deserialize::<R1CSSNARK<E>>(sp)) else {
        return Err("malformed proof".into());
    };
    let pv = verify_linked(&pp, &pvk, &sp, &svk);
    let verify_us = t.elapsed().as_micros();
    let linked = pv.is_some();

    let t = Instant::now();
    let (stmt_ok, expected_given) = match (&pv, &c.expected) {
        (Some((a, b)), Some(e)) => (statement_matches(e, a, b), true),
        _ => (false, c.expected.is_some()),
    };
    let stmt_us = t.elapsed().as_micros();
    let total_us = total.elapsed().as_micros();
    let ok = linked && (stmt_ok || !expected_given);
    let flow = json!({"proofs_linked": linked, "statement_checked": expected_given, "statement_matches": stmt_ok,
        "verify_ms": verify_us / 1000, "vk_load_ms": vk_us / 1000, "vk_digest_ms": digest_us / 1000});
    let load_phase = if iter == 0 { "first" } else { phase };
    for (s, us, ph) in [("vk_load", vk_us, load_phase), ("vk_digest", digest_us, load_phase), ("verify", verify_us, phase),
                        ("statement_check", stmt_us, phase), ("verify_total", total_us, phase)] {
        let mut row = c.out.iter(s, us, ph, iter, flow.clone());
        if s == "vk_load" {
            row["vk_loaded"] = json!(["prepare", "show"]);
        }
        rows.push(row);
    }
    Ok(ok)
}

fn run(o: &Opts) {
    let (ctx, meta) = context(o);
    let dir = fs::canonicalize(o.req("dir")).unwrap_or_else(|e| die(&format!("--dir: {e}")));
    let size: CircuitSize = o.get("size").unwrap_or("2k").parse().unwrap_or_else(|e: String| die(&e));
    let config = PathConfig { base_dir: dir.join("docs"), is_mobile: true, circuit_size: size };
    let warm = o.num("warm", 5);
    let phase_sel = o.get("phase").unwrap_or("all").to_string();
    if !["prepare", "present", "verify", "online", "all"].contains(&phase_sel.as_str()) {
        die("--phase must be prepare|present|verify|online|all");
    }
    let check = !o.flag("no-check");
    let state_dir = o.get("state-dir").map(PathBuf::from).unwrap_or_else(|| dir.join("state"));
    let mut out = Out::open(o.req("out"), ctx);
    let mut dev = device_row(o, &meta);
    dev.insert("phase_selected".into(), phase_sel.clone().into());
    dev.insert("jwt_size".into(), size.as_str().into());
    out.row(Value::Object(dev));

    let expected = ok_or_die(load_expected(&dir));
    let c = Ctx {
        config: config.clone(), dir: dir.clone(), jwt_input: config.base_dir.join("jwt_input.json"),
        show_input: config.base_dir.join("show_input.json"), expected, batch: o.num("batch", 0), out: &mut out,
    };
    let _ = &c.dir;

    let need_prepare = matches!(phase_sel.as_str(), "prepare" | "all" | "present" | "online");
    let need_show = matches!(phase_sel.as_str(), "present" | "online" | "all");
    let mut sizes = Map::new();
    let key_size = |name: &str| fs::metadata(config.key_path(name)).map(|m| m.len()).unwrap_or(0);
    for n in ["prepare_proving.key", "show_proving.key", "prepare_verifying.key", "show_verifying.key"] {
        sizes.insert(format!("{}_{}", size.as_str(), n), key_size(n).into());
    }

    let mut ppk: Option<PK> = None;
    let mut spk: Option<PK> = None;
    let mut load_rows = Vec::new();
    let mut total_load = 0;
    if need_prepare {
        let (k, us) = timed(|| load_proving_key(config.key_path("prepare_proving.key")));
        ppk = Some(k.unwrap_or_else(|e| die(&format!("prepare key: {e}"))));
        total_load += us;
        load_rows.push(c.out.iter("key_load_prepare", us, "first", 0, json!({"key_load_prepare_ms": us / 1000})));
    }
    if need_show {
        let (k, us) = timed(|| load_proving_key(config.key_path("show_proving.key")));
        spk = Some(k.unwrap_or_else(|e| die(&format!("show key: {e}"))));
        total_load += us;
        load_rows.push(c.out.iter("key_load_show", us, "first", 0, json!({"key_load_show_ms": us / 1000})));
    }
    if !load_rows.is_empty() {
        load_rows.push(c.out.iter("load_keys_total", total_load, "first", 0, json!({})));
        c.out.flush(load_rows, None);
    }

    let state_path = |n: &str| state_dir.join(n);
    let mut errors = 0;
    let mut okc = 0;
    let mut last_present_bytes = Value::Null;
    let mut batch_tuple_bytes = 0usize;
    let mut presentation_bytes = 0usize;
    let mut loaded_state: Option<PrepareState> = None;
    if matches!(phase_sel.as_str(), "present" | "online") {
        let (st, us) = timed(|| -> Res<PrepareState> {
            Ok(PrepareState { instance: load_bin(&state_path("prepare_instance.bin"))?, witness: load_bin(&state_path("prepare_witness.bin"))? })
        });
        loaded_state = Some(ok_or_die(st));
        let r = c.out.iter("state_load", us, "first", 0, json!({}));
        c.out.flush(vec![r], None);
    }
    let saved: Option<(Vec<u8>, Vec<u8>)> = if phase_sel == "verify" {
        Some(ok_or_die(load_bin(&state_path("presentation.bin"))))
    } else {
        None
    };

    for it in 0..=warm {
        let phase = if it == 0 { "cold" } else { "warm" };
        let mut rows = Vec::new();
        let res: Res<Option<bool>> = (|| {
            let mut verified: Option<bool> = None;
            let mut prepared: Option<(PrepareState, R1CSSNARK<E>)> = None;
            if matches!(phase_sel.as_str(), "prepare" | "all") {
                prepared = Some(prepare_step(&c, ppk.as_ref().unwrap(), it, phase, &mut rows)?);
            }
            if phase_sel == "prepare" {
                let (st, proof) = prepared.as_ref().unwrap();
                if check {
                    let vk: VK = load_verifying_key(c.config.key_path("prepare_verifying.key")).map_err(|e| e.to_string())?;
                    let pv = proof.verify(&vk).map_err(|e| format!("prepare proof: {e:?}"))?;
                    verified = Some(c.expected.as_ref().map_or(true, |e| decimals(&pv) == e.prepare));
                }
                if o.flag("save-state") && it == warm {
                    save_bin(&state_path("prepare_instance.bin"), &ser(&st.instance, "instance")?)?;
                    save_bin(&state_path("prepare_witness.bin"), &ser(&st.witness, "witness")?)?;
                }
            }
            let mut pres: Option<Presented> = None;
            if need_show {
                let st = prepared.as_ref().map(|p| &p.0).or(loaded_state.as_ref()).ok_or("no prepared state")?;
                let p = present_step(&c, ppk.as_ref().unwrap(), spk.as_ref().unwrap(), st, it, phase, &mut rows)?;
                last_present_bytes = p.state_bytes.clone();
                batch_tuple_bytes = p.prepare_proof.len() + p.state_bytes["blinds"].as_u64().unwrap_or(0) as usize;
                presentation_bytes = p.prepare_proof.len() + p.show_proof.len() + 32 * (p.prepare_pv.len() + p.show_pv.len());
                if o.flag("save-state") && it == warm && phase_sel == "all" {
                    save_bin(&state_path("prepare_instance.bin"), &ser(&st.instance, "instance")?)?;
                    save_bin(&state_path("prepare_witness.bin"), &ser(&st.witness, "witness")?)?;
                }
                pres = Some(p);
            }
            if matches!(phase_sel.as_str(), "online" | "all" | "verify") {
                let (pp, sp) = match (&pres, &saved) {
                    (Some(p), _) => (p.prepare_proof.clone(), p.show_proof.clone()),
                    (None, Some((a, b))) => (a.clone(), b.clone()),
                    _ => return Err("nothing to verify".into()),
                };
                verified = Some(verify_step(&c, &pp, &sp, it, phase, &mut rows)?);
            } else if phase_sel == "present" && check {
                let p = pres.as_ref().unwrap();
                let pvk: VK = load_verifying_key(c.config.key_path("prepare_verifying.key")).map_err(|e| e.to_string())?;
                let svk: VK = load_verifying_key(c.config.key_path("show_verifying.key")).map_err(|e| e.to_string())?;
                let (a, b): (R1CSSNARK<E>, R1CSSNARK<E>) = (
                    bincode::deserialize(&p.prepare_proof).map_err(|e| e.to_string())?,
                    bincode::deserialize(&p.show_proof).map_err(|e| e.to_string())?,
                );
                verified = Some(verify_linked(&a, &pvk, &b, &svk).is_some());
            }
            if o.flag("save-presentation") && it == warm {
                if let Some(p) = &pres {
                    save_bin(&state_path("presentation.bin"), &ser(&(p.prepare_proof.clone(), p.show_proof.clone()), "presentation")?)?;
                }
            }
            Ok(verified)
        })();
        match res {
            Ok(v) => {
                if v != Some(false) {
                    okc += 1;
                } else {
                    errors += 1;
                }
                c.out.flush(rows, v);
            }
            Err(e) => {
                errors += 1;
                eprintln!("iter {it}: {e}");
                c.out.flush(rows, Some(false));
            }
        }
    }

    let prepared_total = last_present_bytes["instance"].as_u64().unwrap_or(0) + last_present_bytes["witness"].as_u64().unwrap_or(0);
    let artifacts = meta.get("witness_artifacts_bytes").and_then(Value::as_u64).unwrap_or(0);
    let key_bytes: u64 = ["prepare_proving.key", "show_proving.key"].iter().map(|n| key_size(n)).sum();
    sizes.insert("kind".into(), "SIZES".into());
    sizes.insert("prepared_state_bytes".into(), last_present_bytes);
    sizes.insert("presentation_bytes".into(), presentation_bytes.into());
    sizes.insert("footprint_bytes".into(), (key_bytes + artifacts + prepared_total).into());
    if c.batch > 0 {
        sizes.insert("batch".into(), c.batch.into());
        sizes.insert("batch_bytes".into(), (c.batch * batch_tuple_bytes).into());
    }
    c.out.row(Value::Object(sizes));
    c.out.row(json!({"kind": "DONE", "ok": okc, "errors": errors, "unchecked": !check}));
    if errors > 0 {
        std::process::exit(1);
    }
}


fn root_limbs(root: &str) -> Res<[String; 2]> {
    let r = BigInt::parse_bytes(root.trim().as_bytes(), 10).ok_or("root is not a decimal integer")?;
    let mask: BigInt = (BigInt::from(1u8) << 128usize) - 1;
    let lo: BigInt = &r & &mask;
    Ok([(&r >> 128usize).to_string(), lo.to_string()])
}

/// One presentation from a staged cell's saved prepared state, then verify and a root/statement check.
/// Prints one JSON line (the last stdout line); `--out <dir>` also writes it to present.json.
fn present_cmd(o: &Opts) {
    let dir = fs::canonicalize(o.req("stage")).unwrap_or_else(|e| die(&format!("--stage: {e}")));
    let meta = ok_or_die(read_json(&dir.join("meta.json")));
    let size: CircuitSize = o.get("size").or(meta["jwt_size"].as_str()).unwrap_or("2k").parse().unwrap_or_else(|e: String| die(&e));
    let config = PathConfig { base_dir: dir.join("docs"), is_mobile: true, circuit_size: size };
    let state_dir = dir.join("state");
    let input = fs::canonicalize(o.req("input")).unwrap_or_else(|e| die(&format!("--input: {e}")));
    let roots = ok_or_die(read_json(Path::new(o.req("expected-roots"))));
    let mut out = Out::open(&o.get("out").map_or("/dev/null".to_string(), |d| format!("{d}/present.bench.jsonl")), Map::new());
    let c = Ctx {
        config: config.clone(), dir: dir.clone(), jwt_input: config.base_dir.join("jwt_input.json"), show_input: input,
        expected: ok_or_die(load_expected(&dir)), batch: 0, out: &mut out,
    };
    let ppk: PK = load_proving_key(config.key_path("prepare_proving.key")).unwrap_or_else(|e| die(&format!("prepare key: {e}")));
    let spk: PK = load_proving_key(config.key_path("show_proving.key")).unwrap_or_else(|e| die(&format!("show key: {e}")));
    let state = PrepareState {
        instance: ok_or_die(load_bin(&state_dir.join("prepare_instance.bin"))),
        witness: ok_or_die(load_bin(&state_dir.join("prepare_witness.bin"))),
    };
    let mut rows = Vec::new();
    let res = present_step(&c, &ppk, &spk, &state, 0, "cold", &mut rows);
    let ms = |step: &str| rows.iter().find(|r| r["step"] == step).map_or(0.0, |r| r["wall_us"].as_f64().unwrap_or(0.0) / 1000.0);
    let (present_total_ms, show_prove_ms) = (ms("present_total"), ms("show_prove"));
    let mut line = json!({"ok": false, "statement_ok": false, "present_total_ms": present_total_ms, "show_prove_ms": show_prove_ms,
        "verify_total_ms": 0.0, "verify_ms": 0.0, "vk_load_ms": 0.0, "vk_digest_ms": 0.0, "statement_check_ms": 0.0, "roots": []});
    if let Ok(p) = res {
        let total = Instant::now();
        let (vks, vk_load_us) = timed(|| load_vks(&config));
        let (digested, vk_digest_us) = timed(|| vks.as_ref().map_err(|e| e.clone()).and_then(|(a, b)| force_digests(&[a, b])));
        let proofs = (bincode::deserialize::<R1CSSNARK<E>>(&p.prepare_proof), bincode::deserialize::<R1CSSNARK<E>>(&p.show_proof));
        if let (Ok((pvk, svk)), Ok(()), (Ok(pp), Ok(sp))) = (vks, digested, proofs) {
            let (linked, verify_us) = timed(|| verify_linked(&pp, &pvk, &sp, &svk));
            if let Some((ppv, spv)) = linked {
                let verify_total_ms = total.elapsed().as_secs_f64() * 1000.0;
                let t = Instant::now();
                let shown = decimals(&spv);
                let mut stmt = true;
                for (key, at) in [("issuerRoot", 1usize), ("revocationRoot", 3)] {
                    stmt &= roots[key].as_str().map_or(false, |r| root_limbs(r).map_or(false, |l| shown.get(at..at + 2) == Some(&l[..])));
                }
                if let Some(e) = &c.expected {
                    // expressionResult (index 0) and the statement tail (5 onward) must match, as must Prepare's values.
                    stmt &= decimals(&ppv) == e.prepare && shown.get(..1) == e.show.get(..1) && shown.get(5..) == e.show.get(5..);
                }
                line["ok"] = true.into();
                line["statement_ok"] = stmt.into();
                line["verify_total_ms"] = verify_total_ms.into();
                line["verify_ms"] = (verify_us as f64 / 1000.0).into();
                line["vk_load_ms"] = (vk_load_us as f64 / 1000.0).into();
                line["vk_digest_ms"] = (vk_digest_us as f64 / 1000.0).into();
                line["statement_check_ms"] = (t.elapsed().as_secs_f64() * 1000.0).into();
                line["roots"] = json!(shown.get(1..5).unwrap_or(&[]));
            }
        }
    } else if let Err(e) = res {
        eprintln!("present: {e}");
    }
    if let Some(d) = o.get("out") {
        ok_or_die(save_bin(&Path::new(d).join("present.json"), line.to_string().as_bytes()));
    }
    println!("{line}");
}

/// Writes the public vectors the circuits produce for the frozen inputs, to compare against proofs.
fn emit_expected(o: &Opts) {
    let size: CircuitSize = o.get("size").unwrap_or("2k").parse().unwrap_or_else(|e: String| die(&e));
    let base = fs::canonicalize(o.req("dir")).unwrap_or_else(|e| die(&format!("--dir: {e}"))).join("docs");
    let config = PathConfig { base_dir: base.clone(), is_mobile: true, circuit_size: size };
    let p = PrepareCircuit::new(config.clone(), Some(base.join("jwt_input.json")));
    let s = ShowCircuit::new(config, Some(base.join("show_input.json")));
    let pv = SpartanCircuit::<E>::public_values(&p).unwrap_or_else(|e| die(&format!("prepare: {e:?}")));
    let sv = SpartanCircuit::<E>::public_values(&s).unwrap_or_else(|e| die(&format!("show: {e:?}")));
    if sv.iter().all(|x| bool::from(x.is_zero())) {
        die("show public values are all zero: witness generation failed");
    }
    let v = json!({"prepare_public": decimals(&pv), "show_public": decimals(&sv)});
    ok_or_die(save_bin(&base.join("expected.json"), v.to_string().as_bytes()));
}

// ---------- shape ----------

fn r1cs_header(path: &Path) -> Res<Value> {
    let b = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if b.len() < 12 || &b[0..4] != b"r1cs" {
        return Err("not an r1cs file".into());
    }
    let u32at = |p: usize| u32::from_le_bytes(b[p..p + 4].try_into().unwrap()) as u64;
    let n_sections = u32at(8);
    let mut pos = 12;
    for _ in 0..n_sections {
        let id = u32at(pos);
        let len = u64::from_le_bytes(b[pos + 4..pos + 12].try_into().unwrap()) as usize;
        pos += 12;
        if id == 1 {
            let n8 = u32at(pos) as usize;
            let h = pos + 4 + n8;
            return Ok(json!({
                "wires": u32at(h), "outputs": u32at(h + 4), "public_inputs": u32at(h + 8), "private_inputs": u32at(h + 12),
                "labels": u64::from_le_bytes(b[h + 16..h + 24].try_into().unwrap()), "constraints": u32at(h + 24),
            }));
        }
        pos += len;
    }
    Err("r1cs header section missing".into())
}

fn shape(o: &Opts) {
    let r1cs = Path::new(o.req("r1cs"));
    let mut row = ok_or_die(r1cs_header(r1cs)).as_object().cloned().unwrap();
    let parsed = load_r1cs::<Scalar>(r1cs).unwrap_or_else(|e| die(&format!("load_r1cs: {e:?}")));
    let (mut a, mut b, mut c) = (0usize, 0usize, 0usize);
    for k in &parsed.constraints {
        a += k.0.len();
        b += k.1.len();
        c += k.2.len();
    }
    if parsed.constraints.len() as u64 != row["constraints"].as_u64().unwrap() {
        die("constraint count differs between header and body");
    }
    row.insert("kind".into(), "SHAPE".into());
    row.insert("loaded_constraints".into(), parsed.constraints.len().into());
    row.insert("loaded_wires".into(), parsed.num_variables.into());
    row.insert("command".into(), std::env::args().collect::<Vec<_>>().join(" ").into());
    row.insert("circuit".into(), o.req("circuit").into());
    row.insert("nnz_a".into(), a.into());
    row.insert("nnz_b".into(), b.into());
    row.insert("nnz_c".into(), c.into());
    row.insert("r1cs_sha256".into(), ok_or_die(file_sha(r1cs)).into());
    let sizes: Option<[usize; 10]> = o.get("pk").map(|p| {
        let pk: PK = load_proving_key(p).unwrap_or_else(|e| die(&format!("pk: {e}")));
        pk.sizes()
    });
    let s = |f: fn(&[usize; 10]) -> usize| sizes.as_ref().map_or(Value::Null, |v| f(v).into());
    row.insert("padded_constraints".into(), s(|v| v[4]));
    row.insert("padded_vars".into(), s(|v| v[5] + v[6] + v[7]));
    row.insert("num_shared".into(), s(|v| v[5]));
    row.insert("num_precommitted".into(), s(|v| v[6]));
    row.insert("num_rest".into(), s(|v| v[7]));
    row.insert("unpadded_constraints".into(), s(|v| v[0]));
    if let Some(m) = o.get("extra").and_then(|x| serde_json::from_str::<Value>(x).ok()).and_then(|v| v.as_object().cloned()) {
        row.extend(m);
    }
    let line = Value::Object(row).to_string();
    match o.get("out") {
        Some(p) => {
            let mut f = fs::OpenOptions::new().create(true).append(true).open(p).unwrap_or_else(|e| die(&e.to_string()));
            let _ = writeln!(f, "{line}");
        }
        None => println!("{line}"),
    }
}

fn digest(o: &Opts) {
    use spartan2::traits::snark::DigestHelperTrait;
    let vk: VK = load_verifying_key(o.req("vk")).unwrap_or_else(|e| die(&format!("vk: {e}")));
    let d = vk.digest().unwrap_or_else(|e| die(&format!("digest: {e:?}")));
    println!("{}", d.iter().map(|b| format!("{b:02x}")).collect::<String>());
}

// ---------- generic path ----------

#[derive(Clone, Debug)]
struct GenericCircuit {
    r1cs: Option<PathBuf>,
    witness: Option<Arc<Vec<Scalar>>>,
    num_public: usize,
    shared: Vec<usize>,
}

impl SpartanCircuit<E> for GenericCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let setup = type_name::<CS>().contains("ShapeCS");
        let loaded = self.r1cs.as_ref().and_then(|p| load_r1cs::<Scalar>(p).ok());
        match (setup, loaded) {
            (true, None) => Err(SynthesisError::AssignmentMissing),
            (true, Some(r)) => {
                let vars = synthesize_all_vars(cs, r, None)?;
                bind_shared(cs, shared, &vars, &self.shared)
            }
            (false, Some(r)) => {
                let w = self.witness.as_ref().ok_or(SynthesisError::AssignmentMissing)?;
                let vars = synthesize_all_vars(cs, r, Some(w.to_vec()))?;
                bind_shared(cs, shared, &vars, &self.shared)
            }
            (false, None) => {
                let w = self.witness.as_ref().ok_or(SynthesisError::AssignmentMissing)?;
                synthesize_witness_only(cs, w, self.num_public)
            }
        }
    }

    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok((1..=self.num_public).map(|i| self.witness.as_ref().map_or(Scalar::ZERO, |w| w[i])).collect())
    }

    fn shared<CS: ConstraintSystem<Scalar>>(&self, cs: &mut CS) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        self.shared
            .iter()
            .enumerate()
            .map(|(k, &i)| {
                let v = self.witness.as_ref().map_or(Scalar::ZERO, |w| w[i]);
                AllocatedNum::alloc(cs.namespace(|| format!("shared{k}")), || Ok(v))
            })
            .collect()
    }

    fn precommitted<CS: ConstraintSystem<Scalar>>(&self, _: &mut CS, _: &[AllocatedNum<Scalar>]) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }

    fn num_challenges(&self) -> usize {
        0
    }
}

struct Layout {
    role: String,
    num_public: usize,
    shared: Vec<usize>,
}

fn load_layout(p: &Path) -> Res<Layout> {
    let v = read_json(p)?;
    Ok(Layout {
        role: v["role"].as_str().unwrap_or("show").to_string(),
        num_public: v["num_public"].as_u64().ok_or("layout: num_public")? as usize,
        shared: v["shared"].as_array().ok_or("layout: shared")?.iter().filter_map(Value::as_u64).map(|x| x as usize).collect(),
    })
}

fn generic_setup(o: &Opts) {
    let r1cs = PathBuf::from(o.req("r1cs"));
    let layout = ok_or_die(load_layout(Path::new(o.req("layout"))));
    let circuit = GenericCircuit { r1cs: Some(r1cs), witness: None, num_public: layout.num_public, shared: layout.shared };
    let (kv, us) = timed(|| R1CSSNARK::<E>::setup(circuit));
    let (pk, vk) = kv.unwrap_or_else(|e| die(&format!("setup: {e:?}")));
    let keys = PathBuf::from(o.req("keys"));
    save_keys(keys.join("generic_proving.key"), keys.join("generic_verifying.key"), &pk, &vk).unwrap_or_else(|e| die(&e.to_string()));
    println!("{}", json!({"kind": "SETUP", "path": "generic", "wall_us": us as u64, "sizes": pk.sizes()}));
}

fn generic_run(o: &Opts) {
    let (ctx, meta) = context(o);
    let dir = fs::canonicalize(o.req("dir")).unwrap_or_else(|e| die(&format!("--dir: {e}")));
    let layout = ok_or_die(load_layout(&dir.join("layout.json")));
    let warm = o.num("warm", 5);
    let mut out = Out::open(o.req("out"), ctx);
    let mut dev = device_row(o, &meta);
    dev.insert("path".into(), "generic".into());
    out.row(Value::Object(dev));

    let (pk, key_us) = timed(|| load_proving_key(dir.join("keys/generic_proving.key")));
    let pk: PK = pk.unwrap_or_else(|e| die(&format!("pk: {e}")));
    let step = if layout.role == "prepare" { "prepare" } else { "show" };
    let r = out.iter(&format!("key_load_{step}"), key_us, "first", 0, json!({}));
    out.flush(vec![r], None);

    let wtns = ok_or_die(parse_witness(&ok_or_die(fs::read(dir.join("generic.wtns")).map_err(|e| e.to_string()))).map_err(|e| format!("wtns: {e:?}")));
    let r1cs = o.flag("r1cs-present").then(|| dir.join("circom/build/generic.r1cs"));
    let circuit = GenericCircuit { r1cs, witness: Some(Arc::new(wtns)), num_public: layout.num_public, shared: layout.shared.clone() };
    let expected_pv = decimals(&SpartanCircuit::<E>::public_values(&circuit).unwrap());
    let (mut okc, mut errors, mut proof_len) = (0, 0, 0);
    for it in 0..=warm {
        let phase = if it == 0 { "cold" } else { "warm" };
        let mut rows = Vec::new();
        let res: Res<bool> = (|| {
            let total = Instant::now();
            let (r, prove_us) = timed(|| prove_circuit_in_memory(circuit.clone(), &pk));
            let (_, inst, wit) = r.map_err(|e| format!("prove: {e:?}"))?;
            let blinds: Vec<Scalar> = (0..inst.num_shared_rows()).map(|_| Scalar::random(&mut ff::derive::rand_core::OsRng)).collect();
            let (r, reblind_us) = timed(|| reblind_in_memory(&pk, inst, wit, &blinds));
            let (proof, _, _) = r.map_err(|e| format!("reblind: {e:?}"))?;
            let bytes = ser(&proof, "proof")?;
            proof_len = bytes.len();
            let total_us = total.elapsed().as_micros();
            rows.push(out.iter(&format!("{step}_prove"), prove_us, phase, it, json!({})));
            rows.push(out.iter(&format!("{step}_reblind"), reblind_us, phase, it, json!({"proof_bytes": bytes.len(), "proof_fingerprint": fingerprint(&bytes)})));
            rows.push(out.iter(&format!("{step}_total"), total_us, phase, it, json!({})));
            let vt = Instant::now();
            let (vk, vk_us) = timed(|| load_verifying_key(dir.join("keys/generic_verifying.key")).map_err(|e| e.to_string()));
            let vk: VK = vk?;
            let (digest, digest_us) = timed(|| force_digests(&[&vk]));
            digest?;
            let (pv, v_us) = timed(|| proof.verify(&vk));
            let pv = pv.map_err(|e| format!("verify: {e:?}"))?;
            let good = decimals(&pv) == expected_pv;
            let load_phase = if it == 0 { "first" } else { phase };
            let mut load_row = out.iter("vk_load", vk_us, load_phase, it, json!({}));
            load_row["vk_loaded"] = json!([step]);
            rows.push(load_row);
            rows.push(out.iter("vk_digest", digest_us, load_phase, it, json!({})));
            rows.push(out.iter("verify", v_us, phase, it, json!({"statement_matches": good})));
            rows.push(out.iter("verify_total", vt.elapsed().as_micros(), phase, it, json!({})));
            Ok(good)
        })();
        match res {
            Ok(g) => {
                if g { okc += 1 } else { errors += 1 }
                out.flush(rows, Some(g));
            }
            Err(e) => {
                errors += 1;
                eprintln!("iter {it}: {e}");
                out.flush(rows, Some(false));
            }
        }
    }
    let key_bytes = fs::metadata(dir.join("keys/generic_proving.key")).map(|m| m.len()).unwrap_or(0);
    out.row(json!({"kind": "SIZES", "generic_proving.key": key_bytes, "presentation_bytes": proof_len}));
    out.row(json!({"kind": "DONE", "ok": okc, "errors": errors}));
    if errors > 0 {
        std::process::exit(1);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    SMOKE.store(args.iter().any(|a| a == "--smoke"), std::sync::atomic::Ordering::Relaxed);
    match args.first().map(String::as_str) {
        Some("run") => run(&Opts::parse(&args[1..])),
        Some("present") => present_cmd(&Opts::parse(&args[1..])),
        Some("emit-expected") => emit_expected(&Opts::parse(&args[1..])),
        Some("shape") => shape(&Opts::parse(&args[1..])),
        Some("digest") => digest(&Opts::parse(&args[1..])),
        Some("generic") => match args.get(1).map(String::as_str) {
            Some("setup") => generic_setup(&Opts::parse(&args[2..])),
            Some("run") => generic_run(&Opts::parse(&args[2..])),
            _ => die("generic {setup|run}"),
        },
        _ => die("usage: openac_bench {run|present|emit-expected|shape|digest|generic} ..."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_limbs_split_at_128_bits() {
        let hi: BigInt = BigInt::from(7u8) << 128usize;
        let root = (hi + BigInt::from(9u8)).to_string();
        assert_eq!(root_limbs(&root).unwrap(), ["7".to_string(), "9".to_string()]);
        assert!(root_limbs("0x10").is_err());
    }

    #[test]
    fn opts_parse_flags_and_values() {
        let a: Vec<String> = ["--smoke", "--dir", "x", "--no-check", "--warm", "3"].map(String::from).to_vec();
        let o = Opts::parse(&a);
        assert!(o.flag("no-check") && o.flag("smoke"));
        assert_eq!((o.get("dir"), o.num("warm", 0)), (Some("x"), 3));
    }
}

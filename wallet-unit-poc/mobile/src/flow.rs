//! In-memory Prepare / Present / Verify flow behind the `flow_*` exports.
//!
//! Keys are loaded once into `SESSION`; nothing under the documents path is
//! written. Proving clones the `Arc`s out first so the lock is never held while
//! a proof runs. Key loads do hold it, so `unload` can't race a load and leave a
//! key resident.

use crate::statement::{check_statement, parse_decimal_scalars, scalar_to_decimal};
use crate::{
    make_config, FlowExpectedStatement, FlowPrepareResult, FlowPresentation, FlowVerifyResult,
    ZkProofError,
};
use ecdsa_spartan2::{
    load_proving_key, load_verifying_key,
    paths::keys::{PREPARE_VERIFYING_KEY, SHOW_VERIFYING_KEY},
    prover::verify_linked,
    prove_circuit_in_memory, reblind_in_memory, PrepareCircuit, ShowCircuit, E, Scalar,
};
use ff::Field;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use group::GroupEncoding;
use spartan2::{
    r1cs::{R1CSWitness, SplitR1CSInstance},
    traits::{snark::R1CSSNARKTrait, Engine},
    zk_spartan::R1CSSNARK,
};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

pub type ProvingKey = <R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey;
pub type VerifierKey = <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey;

/// The Prepare proof's instance and witness, kept so each presentation can
/// reblind them with fresh randomness.
struct PrepareState {
    instance: SplitR1CSInstance<E>,
    witness: R1CSWitness<E>,
}

pub struct Session {
    prepare_pk: Option<Arc<ProvingKey>>,
    show_pk: Option<Arc<ProvingKey>>,
    prepare_vk: Option<Arc<VerifierKey>>,
    show_vk: Option<Arc<VerifierKey>>,
    prepare: Option<Arc<PrepareState>>,
}

impl Session {
    const fn empty() -> Self {
        Session {
            prepare_pk: None,
            show_pk: None,
            prepare_vk: None,
            show_vk: None,
            prepare: None,
        }
    }
}

pub static SESSION: Mutex<Session> = Mutex::new(Session::empty());

fn session() -> MutexGuard<'static, Session> {
    SESSION.lock().unwrap_or_else(|e| e.into_inner())
}

fn ms_since(start: std::time::Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

fn require<T>(slot: &Option<Arc<T>>, what: &str) -> Result<Arc<T>, ZkProofError> {
    slot.clone().ok_or_else(|| ZkProofError::SetupRequired {
        message: format!("{what} not loaded"),
    })
}

fn proving_failed(e: impl std::fmt::Debug) -> ZkProofError {
    ZkProofError::ProofGenerationFailed {
        message: format!("{e:?}"),
    }
}

/// Lowercase hex of the first 8 bytes of SHA-256 over `bytes`.
pub fn fingerprint(bytes: &[u8]) -> String {
    Sha256::digest(bytes)[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn serialize<T: serde::Serialize>(value: &T, what: &str) -> Result<Vec<u8>, ZkProofError> {
    bincode::serialize(value).map_err(|e| ZkProofError::IoError {
        message: format!("Failed to serialize {what}: {e}"),
    })
}

/// Compressed-point hex of each commitment point. Debug output would expose
/// the projective `z`, which differs between equal points after reblinding.
fn encode_points(points: &[<E as Engine>::GE]) -> String {
    points
        .iter()
        .flat_map(|p| p.to_bytes().as_ref().to_vec())
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub(crate) fn comm_w_shared_hex(instance: &SplitR1CSInstance<E>) -> String {
    instance
        .comm_W_shared
        .as_ref()
        .map(|c| encode_points(&c.comm))
        .unwrap_or_default()
}

fn load_pk(path: &str) -> Result<(ProvingKey, u64), ZkProofError> {
    let start = std::time::Instant::now();
    let pk = load_proving_key(path).map_err(|e| ZkProofError::FileNotFound {
        message: format!("Failed to load proving key '{path}': {e}"),
    })?;
    Ok((pk, ms_since(start)))
}

/// Empties the slot before loading so a reload never holds two copies of a
/// ~430 MB key. A failed load leaves it empty.
fn load_into(
    path: &str,
    slot_of: impl FnOnce(&mut Session) -> &mut Option<Arc<ProvingKey>>,
) -> Result<u64, ZkProofError> {
    let mut session = session();
    let slot = slot_of(&mut session);
    *slot = None;
    let (pk, ms) = load_pk(path)?;
    *slot = Some(Arc::new(pk));
    Ok(ms)
}

pub fn load_prepare_key(path: &str) -> Result<u64, ZkProofError> {
    load_into(path, |s| &mut s.prepare_pk)
}

pub fn load_show_key(path: &str) -> Result<u64, ZkProofError> {
    load_into(path, |s| &mut s.show_pk)
}

#[cfg(feature = "native-zk")]
fn prepare_witness(
    config: &ecdsa_spartan2::PathConfig,
    input: &Path,
) -> Result<Vec<Scalar>, ZkProofError> {
    ecdsa_spartan2::generate_prepare_witness(config, Some(input)).map_err(proving_failed)
}

#[cfg(not(feature = "native-zk"))]
fn prepare_witness(
    _config: &ecdsa_spartan2::PathConfig,
    _input: &Path,
) -> Result<Vec<Scalar>, ZkProofError> {
    Err(ZkProofError::ProofGenerationFailed {
        message: "built without native-zk: no witness generator".into(),
    })
}

pub fn prepare(
    documents_path: &str,
    input_path: &str,
) -> Result<FlowPrepareResult, ZkProofError> {
    let pk = {
        let mut session = session();
        // The cached vk is ~430 MB; free it so it doesn't stack on the proving peak.
        session.prepare_vk = None;
        require(&session.prepare_pk, "prepare key")?
    };
    let input = Path::new(input_path);
    if !input.exists() {
        return Err(ZkProofError::FileNotFound {
            message: format!("prepare input '{input_path}' not found"),
        });
    }
    let config = make_config(documents_path);

    let start = std::time::Instant::now();
    let witness = prepare_witness(&config, input)?;
    let witness_ms = ms_since(start);

    let circuit = PrepareCircuit::with_witness_for_size(witness, config.circuit_size);
    let (proof, instance, witness) = prove_circuit_in_memory(circuit, &pk).map_err(proving_failed)?;
    let prove_ms = ms_since(start) - witness_ms;

    let proof_bytes = serialize(&proof, "prepare proof")?;
    let instance_bytes = serialize(&instance, "prepare instance")?.len() as u64;
    let result = FlowPrepareResult {
        witness_ms,
        prove_ms,
        proof_bytes: proof_bytes.len() as u64,
        instance_bytes,
        proof_fingerprint: fingerprint(&proof_bytes),
        comm_w_shared: comm_w_shared_hex(&instance),
    };
    session().prepare = Some(Arc::new(PrepareState { instance, witness }));
    Ok(result)
}

pub fn present(
    documents_path: &str,
    show_input_path: &str,
) -> Result<FlowPresentation, ZkProofError> {
    let (prepare_pk, show_pk, state) = {
        let mut session = session();
        // Same reason as in `prepare`: keep the ~430 MB vk out of the proving peak.
        session.prepare_vk = None;
        (
            require(&session.prepare_pk, "prepare key")?,
            require(&session.show_pk, "show key")?,
            require(&session.prepare, "prepare proof (run flow_prepare first)")?,
        )
    };
    let input = Path::new(show_input_path);
    if !input.exists() {
        return Err(ZkProofError::FileNotFound {
            message: format!("show input '{show_input_path}' not found"),
        });
    }
    let config = make_config(documents_path);
    let total = std::time::Instant::now();

    let start = std::time::Instant::now();
    let circuit = ShowCircuit::new(config, Some(input.to_path_buf()));
    let (_, show_instance, show_witness) =
        prove_circuit_in_memory(circuit, &show_pk).map_err(proving_failed)?;
    let show_prove_ms = ms_since(start);

    let rows = state.instance.num_shared_rows();
    if show_instance.num_shared_rows() != rows {
        return Err(ZkProofError::ProofGenerationFailed {
            message: format!(
                "prepare has {rows} shared rows but show has {}",
                show_instance.num_shared_rows()
            ),
        });
    }
    let blinds: Vec<Scalar> = (0..rows).map(|_| Scalar::random(&mut OsRng)).collect();

    // Reblinding consumes its instance and witness; the stored Prepare state stays reusable.
    let start = std::time::Instant::now();
    let (prepare_proof, prepare_instance, _) = reblind_in_memory(
        &prepare_pk,
        state.instance.clone(),
        state.witness.clone(),
        &blinds,
    )
    .map_err(proving_failed)?;
    let prepare_reblind_ms = ms_since(start);

    let start = std::time::Instant::now();
    let (show_proof, show_instance, _) =
        reblind_in_memory(&show_pk, show_instance, show_witness, &blinds).map_err(proving_failed)?;
    let show_reblind_ms = ms_since(start);

    let prepare_proof = serialize(&prepare_proof, "prepare proof")?;
    let show_proof = serialize(&show_proof, "show proof")?;
    Ok(FlowPresentation {
        prepare_fingerprint: fingerprint(&prepare_proof),
        show_fingerprint: fingerprint(&show_proof),
        prepare_comm_w_shared: comm_w_shared_hex(&prepare_instance),
        show_comm_w_shared: comm_w_shared_hex(&show_instance),
        prepare_proof,
        show_proof,
        show_prove_ms,
        prepare_reblind_ms,
        show_reblind_ms,
        total_ms: ms_since(total),
    })
}

fn load_vk(path: std::path::PathBuf, what: &str) -> Result<Arc<VerifierKey>, ZkProofError> {
    if !path.exists() {
        return Err(ZkProofError::SetupRequired {
            message: format!("{what} verifying key not found at '{}'", path.display()),
        });
    }
    let vk = load_verifying_key(&path).map_err(|e| ZkProofError::FileNotFound {
        message: format!("Failed to load {what} verifying key: {e}"),
    })?;
    Ok(Arc::new(vk))
}

fn verifying_keys(
    documents_path: &str,
) -> Result<(Arc<VerifierKey>, Arc<VerifierKey>, u64), ZkProofError> {
    let config = make_config(documents_path);
    let mut session = session();
    let start = std::time::Instant::now();
    let prepare_vk = match session.prepare_vk.clone() {
        Some(vk) => vk,
        None => {
            let vk = load_vk(config.key_path(PREPARE_VERIFYING_KEY), "prepare")?;
            session.prepare_vk = Some(vk.clone());
            vk
        }
    };
    let show_vk = match session.show_vk.clone() {
        Some(vk) => vk,
        None => {
            let vk = load_vk(config.key_path(SHOW_VERIFYING_KEY), "show")?;
            session.show_vk = Some(vk.clone());
            vk
        }
    };
    Ok((prepare_vk, show_vk, ms_since(start)))
}

fn rejected(vk_load_ms: u64, verify_ms: u64, failure: &str) -> FlowVerifyResult {
    FlowVerifyResult {
        valid: false,
        expression_result: false,
        proofs_linked: false,
        issuer_trusted: false,
        normalization_matches: false,
        nonce_matches: false,
        policy_matches: false,
        issuer_key_x: String::new(),
        issuer_key_y: String::new(),
        vk_load_ms,
        verify_ms,
        failure: Some(failure.into()),
    }
}

pub fn verify(
    documents_path: &str,
    prepare_proof: &[u8],
    show_proof: &[u8],
    expected: &FlowExpectedStatement,
) -> Result<FlowVerifyResult, ZkProofError> {
    let invalid = |what: &str, e: String| ZkProofError::InvalidInput {
        message: format!("{what}: {e}"),
    };
    let expected_prepare = parse_decimal_scalars(&expected.prepare_public_values)
        .map_err(|e| invalid("prepare_public_values", e))?;
    let expected_show = parse_decimal_scalars(&expected.show_statement)
        .map_err(|e| invalid("show_statement", e))?;

    let (prepare_vk, show_vk, vk_load_ms) = verifying_keys(documents_path)?;

    let start = std::time::Instant::now();
    let (Ok(prepare_proof), Ok(show_proof)) = (
        bincode::deserialize::<R1CSSNARK<E>>(prepare_proof),
        bincode::deserialize::<R1CSSNARK<E>>(show_proof),
    ) else {
        return Ok(rejected(vk_load_ms, ms_since(start), "malformed proof"));
    };

    let Some((prepare_pv, show_pv)) =
        verify_linked(&prepare_proof, &prepare_vk, &show_proof, &show_vk)
    else {
        return Ok(rejected(
            vk_load_ms,
            ms_since(start),
            "proofs invalid or not linked",
        ));
    };
    let verify_ms = ms_since(start);

    let check = check_statement(&prepare_pv, &show_pv, &expected_prepare, &expected_show);
    let valid = check.issuer_trusted
        && check.normalization_matches
        && check.nonce_matches
        && check.policy_matches;
    let issuer_key = |i: usize| prepare_pv.get(i).map(scalar_to_decimal).unwrap_or_default();
    Ok(FlowVerifyResult {
        valid,
        expression_result: check.expression_result,
        proofs_linked: true,
        issuer_trusted: check.issuer_trusted,
        normalization_matches: check.normalization_matches,
        nonce_matches: check.nonce_matches,
        policy_matches: check.policy_matches,
        issuer_key_x: issuer_key(0),
        issuer_key_y: issuer_key(1),
        vk_load_ms,
        verify_ms,
        failure: check.failure,
    })
}

pub fn unload() {
    *session() = Session::empty();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{flow_present, flow_prepare, flow_unload, flow_verify};

    /// Tests share `SESSION`; hold this while touching it.
    static SESSION_LOCK: Mutex<()> = Mutex::new(());

    pub(super) fn lock() -> MutexGuard<'static, ()> {
        SESSION_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn expected() -> FlowExpectedStatement {
        FlowExpectedStatement {
            prepare_public_values: vec!["1".into(); 6],
            show_statement: vec!["1".into(); 155],
        }
    }

    fn assert_setup_required<T: std::fmt::Debug>(r: Result<T, ZkProofError>) {
        assert!(
            matches!(r, Err(ZkProofError::SetupRequired { .. })),
            "expected SetupRequired, got {r:?}"
        );
    }

    #[test]
    fn fingerprint_is_deterministic_16_hex_chars() {
        let a = fingerprint(b"proof bytes");
        assert_eq!(a, fingerprint(b"proof bytes"));
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
        assert_ne!(a, fingerprint(b"proof byteS"));
    }

    #[test]
    fn fingerprint_matches_sha256_prefix() {
        // sha256("") = e3b0c44298fc1c14...
        assert_eq!(fingerprint(b""), "e3b0c44298fc1c14");
    }

    #[test]
    fn point_encoding_ignores_projective_representation() {
        use group::Group;
        let g = <E as Engine>::GE::generator();
        let a = g.double() + g;
        let b = g.double().double() - g;
        assert_ne!(format!("{a:?}"), format!("{b:?}"), "need two representations");
        assert_eq!(encode_points(&[a, g]), encode_points(&[b, g]));
        assert_ne!(encode_points(&[a]), encode_points(&[g]));
        assert_eq!(encode_points(&[g]).len(), 2 * 33);
    }

    #[test]
    fn prepare_needs_setup_when_nothing_loaded() {
        let _g = lock();
        flow_unload();
        assert_setup_required(flow_prepare("/nonexistent".into(), "/nonexistent/in.json".into()));
    }

    #[test]
    fn present_needs_setup_when_nothing_loaded() {
        let _g = lock();
        flow_unload();
        assert_setup_required(flow_present("/nonexistent".into(), "/nonexistent/in.json".into()));
    }

    #[test]
    fn verify_needs_setup_when_no_verifying_keys() {
        let _g = lock();
        flow_unload();
        let temp = tempfile::tempdir().unwrap();
        let docs = temp.path().to_string_lossy().into_owned();
        assert_setup_required(flow_verify(docs, vec![0; 8], vec![0; 8], expected()));
    }

    #[test]
    fn verify_rejects_unparsable_expected_values() {
        let _g = lock();
        flow_unload();
        let mut bad = expected();
        bad.show_statement[3] = "not a number".into();
        let r = flow_verify("/nonexistent".into(), vec![], vec![], bad);
        assert!(matches!(r, Err(ZkProofError::InvalidInput { .. })), "{r:?}");
    }

    #[test]
    fn unload_clears_the_session() {
        let _g = lock();
        flow_unload();
        let s = session();
        assert!(s.prepare_pk.is_none() && s.show_pk.is_none());
        assert!(s.prepare_vk.is_none() && s.show_vk.is_none() && s.prepare.is_none());
    }
}

#[cfg(all(test, feature = "native-zk"))]
mod e2e_tests {
    use super::*;
    use crate::{
        flow_present, flow_prepare, flow_unload, flow_verify, load_prepare_key, load_show_key,
        setup_jwt_keys, setup_show_keys,
    };
    use ecdsa_spartan2::paths::keys::{PREPARE_PROVING_KEY, SHOW_PROVING_KEY};
    use serde::Deserialize;
    use std::fs;
    use std::path::PathBuf;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Bundle {
        requests: Vec<Request>,
        scenarios: Vec<Scenario>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Request {
        id: String,
        show_input: serde_json::Value,
        expected: Expected,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Expected {
        prepare_public_values: Vec<String>,
        show_statement: Vec<String>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Scenario {
        id: String,
        present_for: String,
        verify_against: String,
        expect: String,
    }

    fn mobile_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    /// Lays out the documents dir the way the app does: the r1cs files that
    /// key setup reads, plus the Prepare input.
    fn setup_docs(root: &Path) -> String {
        let docs = root.join("circom");
        let build = mobile_dir().parent().unwrap().join("circom/build");
        for (src, dir, name) in [
            ("jwt_2k/jwt_2k_js/jwt_2k.r1cs", "build/jwt/jwt_js", "jwt.r1cs"),
            ("show/show_js/show.r1cs", "build/show/show_js", "show.r1cs"),
        ] {
            fs::create_dir_all(docs.join(dir)).unwrap();
            fs::copy(build.join(src), docs.join(dir).join(name)).unwrap();
        }
        fs::copy(
            mobile_dir().join("flutter/assets/circom/jwt_input.json"),
            docs.join("jwt_input.json"),
        )
        .unwrap();
        docs.to_string_lossy().into_owned()
    }

    #[test]
    #[ignore = "Long-running e2e; needs circom/build and flutter/assets/flow/bundle.json (scripts/prepare-assets.sh)"]
    fn e2e_flow_fixture() {
        let _guard = super::tests::lock();
        let bundle_path = mobile_dir().join("flutter/assets/flow/bundle.json");
        let bundle: Bundle =
            serde_json::from_slice(&fs::read(&bundle_path).expect("read flow bundle"))
                .expect("parse flow bundle");
        let request = |id: &str| {
            bundle
                .requests
                .iter()
                .find(|r| r.id == id)
                .unwrap_or_else(|| panic!("request {id} missing"))
        };

        let temp = tempfile::tempdir().unwrap();
        let docs = setup_docs(temp.path());
        flow_unload();
        setup_jwt_keys(docs.clone()).expect("setup jwt keys");
        setup_show_keys(docs.clone()).expect("setup show keys");
        let config = make_config(&docs);
        let key = |name| config.key_path(name).to_string_lossy().into_owned();
        load_prepare_key(key(PREPARE_PROVING_KEY)).expect("load prepare key");
        load_show_key(key(SHOW_PROVING_KEY)).expect("load show key");

        flow_prepare(docs.clone(), format!("{docs}/jwt_input.json")).expect("prepare");

        let statement = |e: &Expected| FlowExpectedStatement {
            prepare_public_values: e.prepare_public_values.clone(),
            show_statement: e.show_statement.clone(),
        };
        let mut presented = None;
        for scenario in &bundle.scenarios {
            let show_input = temp.path().join(format!("show_{}.json", scenario.id));
            fs::write(
                &show_input,
                serde_json::to_vec(&request(&scenario.present_for).show_input).unwrap(),
            )
            .unwrap();
            let show_input = show_input.to_string_lossy().into_owned();

            let first = flow_present(docs.clone(), show_input.clone()).expect("present #1");
            let second = flow_present(docs.clone(), show_input).expect("present #2");
            assert_ne!(first.prepare_fingerprint, second.prepare_fingerprint, "{}", scenario.id);
            assert_ne!(first.show_fingerprint, second.show_fingerprint, "{}", scenario.id);
            assert_eq!(first.prepare_comm_w_shared, first.show_comm_w_shared);
            assert_eq!(second.prepare_comm_w_shared, second.show_comm_w_shared);

            let expected = &request(&scenario.verify_against).expected;
            let result = flow_verify(
                docs.clone(),
                first.prepare_proof.clone(),
                first.show_proof.clone(),
                statement(expected),
            )
            .expect("verify");

            let verdict = match (result.valid, result.expression_result) {
                (true, true) => "accepted",
                (true, false) => "policy_false",
                (false, _) => "rejected",
            };
            assert_eq!(verdict, scenario.expect, "{}: {:?}", scenario.id, result.failure);
            assert!(result.proofs_linked, "{}", scenario.id);
            let checks = [
                result.issuer_trusted,
                result.normalization_matches,
                result.nonce_matches,
                result.policy_matches,
            ];
            match scenario.id.as_str() {
                "replay" => assert_eq!(checks, [true, true, false, true]),
                "untrustedIssuer" => assert_eq!(checks, [false, true, true, true]),
                _ => assert_eq!(checks, [true; 4], "{}", scenario.id),
            }
            if scenario.id == "over18" {
                presented = Some((first.prepare_proof, first.show_proof, expected));
            }
        }

        let (prepare_proof, show_proof, expected) = presented.expect("over18 scenario");
        let mut flipped = show_proof.clone();
        let mid = flipped.len() / 2;
        flipped[mid] ^= 0x01;
        let truncated = prepare_proof[..prepare_proof.len() / 2].to_vec();
        for (name, prepare, show) in [
            ("flipped show byte", prepare_proof.clone(), flipped),
            ("truncated prepare", truncated, show_proof.clone()),
        ] {
            let r = flow_verify(docs.clone(), prepare, show, statement(expected))
                .unwrap_or_else(|e| panic!("{name}: expected Ok(invalid), got {e:?}"));
            assert!(!r.valid, "{name}");
            assert!(r.failure.is_some(), "{name}");
        }
        flow_unload();
    }
}

//! CLI for running the Spartan-2 Prepare and Show circuits.
//!
//! Usage examples:
//!   cargo run --release -- prepare run --size 1k --input ../circom/inputs/jwt/1k/default.json
//!   cargo run --release -- show prove --size 2k
//!   cargo run --release -- prepare setup --size 1k
//!   cargo run --release -- show verify --size 1k
//!   cargo run --release -- benchmark --size 2k
//!   cargo run --release -- benchmark-all
//!   cargo run --release -- setup-sha256
//!   cargo run --release -- prove-sha256 [--out DIR]
//!   cargo run --release -- verify-sha256 [--proof PATH]
//!
//! Typical post-keygen flow:
//! 0. `prepare setup --size Xk` and `show setup --size Xk` — generate keys (one-time, slow).
//! 1. `generate_shared_blinds` — derive shared blinding factors.
//! 2. `prove_prepare` — produce the initial Prepare proof.
//! 3. `reblind_prepare` — reblind the Prepare proof.
//! 4. `prove_show` — produce the Show proof using the shared witness commitment.
//! 5. `reblind_show` — reblind the Show proof.

use ecdsa_spartan2::{
    circuit_size::CircuitSize,
    generate_shared_blinds, load_instance, load_proof, load_proving_key, load_shared_blinds,
    load_verifying_key, load_witness,
    paths::keys::{
        MDOC_INSTANCE, MDOC_PROOF, MDOC_PROVING_KEY, MDOC_VERIFYING_KEY, MDOC_WITNESS,
        PREPARE_INSTANCE, PREPARE_PROOF, PREPARE_PROVING_KEY, PREPARE_VERIFYING_KEY,
        PREPARE_WITNESS, SHARED_BLINDS, SHOW_INSTANCE, SHOW_PROOF, SHOW_PROVING_KEY,
        SHA256_PROOF, SHA256_PROVING_KEY, SHA256_VERIFYING_KEY,
        SHOW_VERIFYING_KEY, SHOW_WITNESS,
    },
    prove_circuit, prove_circuit_in_memory, prove_circuit_with_pk, reblind, reblind_with_loaded_data,
    run_circuit,
    save_keys, setup_circuit_keys, setup_circuit_keys_no_save, verify_circuit,
    verify_circuit_with_loaded_data, MdocCircuit, PathConfig, PrepareCircuit, Scalar, Sha256Circuit, ShowCircuit,
    E,
};
use ecdsa_spartan2::circuits::sha256_circuit::{sha256_digest_bits, sha256_fixed_message};
use ecdsa_spartan2::setup::save_proof;
use ecdsa_spartan2::utils::{calculate_jwt_output_indices, calculate_mdoc_output_indices};
use ff::Field;
use std::{env::args, fs, ops::Range, path::PathBuf, process, time::Instant};
use tracing::info;
use tracing_subscriber::EnvFilter;

const NUM_SHARED: usize = 1;

fn get_file_size(path: &str) -> u64 {
    fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

#[derive(Debug)]
struct BenchmarkResults {
    size: CircuitSize,
    prepare_setup_ms: Option<u128>,
    show_setup_ms: Option<u128>,
    generate_blinds_ms: u128,
    prove_prepare_ms: u128,
    reblind_prepare_ms: u128,
    prove_show_ms: u128,
    reblind_show_ms: u128,
    verify_prepare_ms: u128,
    verify_show_ms: u128,

    prepare_proving_key_bytes: u64,
    prepare_verifying_key_bytes: u64,
    show_proving_key_bytes: u64,
    show_verifying_key_bytes: u64,
    prepare_proof_bytes: u64,
    show_proof_bytes: u64,
    prepare_witness_bytes: u64,
    show_witness_bytes: u64,
}

impl BenchmarkResults {
    fn format_size(bytes: u64) -> String {
        if bytes < 1024 {
            format!("{} B", bytes)
        } else if bytes < 1024 * 1024 {
            format!("{:.2} KB", bytes as f64 / 1024.0)
        } else {
            format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
        }
    }

    fn print_summary(&self) {
        println!("\n╔════════════════════════════════════════════════════╗");
        println!(
            "║   BENCHMARK RESULTS — circuit size: {:>4}           ║",
            self.size
        );
        println!("╠════════════════════════════════════════════════════╣");
        println!("║ TIMING MEASUREMENTS                                ║");
        println!("╠════════════════════════════════════════════════════╣");
        if let Some(ms) = self.prepare_setup_ms {
            println!("║ Prepare Setup:          {:>10} ms          ║", ms);
        }
        if let Some(ms) = self.show_setup_ms {
            println!("║ Show Setup:             {:>10} ms          ║", ms);
        }
        println!(
            "║ Generate Blinds:        {:>10} ms          ║",
            self.generate_blinds_ms
        );
        println!(
            "║ Prove Prepare:          {:>10} ms          ║",
            self.prove_prepare_ms
        );
        println!(
            "║ Reblind Prepare:        {:>10} ms          ║",
            self.reblind_prepare_ms
        );
        println!(
            "║ Prove Show:             {:>10} ms          ║",
            self.prove_show_ms
        );
        println!(
            "║ Reblind Show:           {:>10} ms          ║",
            self.reblind_show_ms
        );
        println!(
            "║ Verify Prepare:         {:>10} ms          ║",
            self.verify_prepare_ms
        );
        println!(
            "║ Verify Show:            {:>10} ms          ║",
            self.verify_show_ms
        );
        println!("╠════════════════════════════════════════════════════╣");
        println!("║ SIZE MEASUREMENTS                                  ║");
        println!("╠════════════════════════════════════════════════════╣");
        println!(
            "║ Prepare Proving Key:    {:>14}         ║",
            Self::format_size(self.prepare_proving_key_bytes)
        );
        println!(
            "║ Prepare Verifying Key:  {:>14}         ║",
            Self::format_size(self.prepare_verifying_key_bytes)
        );
        println!(
            "║ Show Proving Key:       {:>14}         ║",
            Self::format_size(self.show_proving_key_bytes)
        );
        println!(
            "║ Show Verifying Key:     {:>14}         ║",
            Self::format_size(self.show_verifying_key_bytes)
        );
        println!(
            "║ Prepare Proof:          {:>14}         ║",
            Self::format_size(self.prepare_proof_bytes)
        );
        println!(
            "║ Show Proof:             {:>14}         ║",
            Self::format_size(self.show_proof_bytes)
        );
        println!(
            "║ Prepare Witness:        {:>14}         ║",
            Self::format_size(self.prepare_witness_bytes)
        );
        println!(
            "║ Show Witness:           {:>14}         ║",
            Self::format_size(self.show_witness_bytes)
        );
        println!("╚════════════════════════════════════════════════════╝\n");
    }
}

fn print_comparison_table(results: &[BenchmarkResults]) {
    if results.is_empty() {
        println!("No results to display.");
        return;
    }

    let col_w = 12usize;
    let label_w = 24usize;

    let hdr: Vec<String> = results
        .iter()
        .map(|r| format!("{:>width$}", r.size, width = col_w))
        .collect();
    let top_sep = "═".repeat(col_w + 1);
    let mid_sep = "─".repeat(col_w + 1);

    print!("╔{:═<width$}╦", "", width = label_w + 2);
    println!(
        "{}╗",
        hdr.iter()
            .map(|_| top_sep.clone())
            .collect::<Vec<_>>()
            .join("╦")
    );

    print!("║ {:width$} ║", "Metric", width = label_w);
    for h in &hdr {
        print!("{}║", h);
    }
    println!();

    print!("╠{:═<width$}╬", "", width = label_w + 2);
    println!(
        "{}╣",
        hdr.iter()
            .map(|_| top_sep.clone())
            .collect::<Vec<_>>()
            .join("╬")
    );

    let row = |label: &str, vals: &[String]| {
        let mut s = format!("║ {:width$} ║", label, width = label_w);
        for v in vals {
            s.push_str(&format!("{:>width$}║", v, width = col_w + 1));
        }
        println!("{}", s);
    };

    let ms = |f: fn(&BenchmarkResults) -> u128| -> Vec<String> {
        results.iter().map(|r| format!("{} ms", f(r))).collect()
    };
    let sz = |f: fn(&BenchmarkResults) -> u64| -> Vec<String> {
        results
            .iter()
            .map(|r| BenchmarkResults::format_size(f(r)))
            .collect()
    };

    row("Generate Blinds", &ms(|r| r.generate_blinds_ms));
    row("Prove Prepare", &ms(|r| r.prove_prepare_ms));
    row("Reblind Prepare", &ms(|r| r.reblind_prepare_ms));
    row("Prove Show", &ms(|r| r.prove_show_ms));
    row("Reblind Show", &ms(|r| r.reblind_show_ms));
    row("Verify Prepare", &ms(|r| r.verify_prepare_ms));
    row("Verify Show", &ms(|r| r.verify_show_ms));

    print!("╠{:═<width$}╬", "", width = label_w + 2);
    println!(
        "{}╣",
        hdr.iter()
            .map(|_| top_sep.clone())
            .collect::<Vec<_>>()
            .join("╬")
    );

    row("Prepare Proof", &sz(|r| r.prepare_proof_bytes));
    row("Show Proof", &sz(|r| r.show_proof_bytes));
    row("Prepare Proving Key", &sz(|r| r.prepare_proving_key_bytes));
    row("Show Proving Key", &sz(|r| r.show_proving_key_bytes));

    print!("╚{:═<width$}╩", "", width = label_w + 2);
    println!(
        "{}╝\n",
        results
            .iter()
            .map(|_| mid_sep.replace('─', "═"))
            .collect::<Vec<_>>()
            .join("╩")
    );
}

/// Print the issuer key a credential proof was built under, plus how each claim
/// value in its public IO was normalized.
///
/// `public_values[i]` is `witness[i + 1]`, so the 1-based layout indices are
/// shifted by one here.
///
/// Printed rather than checked: this pipeline has no trust store or policy to
/// compare against. Applications that do have one can use
/// `utils::check_issuer_key_binding` and compare the normalization against the
/// formats their predicates expect.
fn print_public_statement(
    public_values: &[Scalar],
    issuer_key_x_index: usize,
    flags: Range<usize>,
    formats: Range<usize>,
) {
    let at = |i: usize| public_values.get(i.wrapping_sub(1));

    match (at(issuer_key_x_index), at(issuer_key_x_index + 1)) {
        (Some(x), Some(y)) => println!("  issuer key: x={x:?}\n              y={y:?}"),
        _ => println!("  issuer key: <unavailable: proof exposed too few public values>"),
    }

    // Flags and format codes are small integers; print the trailing hex digits
    // of each scalar rather than all 64.
    let render = |range: Range<usize>| {
        range
            .map(|i| match at(i) {
                Some(v) => {
                    let s = format!("{v:?}");
                    format!("0x{}", s.trim_start_matches("0x").trim_start_matches('0'))
                }
                None => "?".to_string(),
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    println!(
        "  claim normalization: decoded=[{}] formats=[{}]\n",
        render(flags),
        render(formats),
    );
}

/// Prove + reblind + verify pipeline using pre-existing keys on disk.
fn run_prove_pipeline(
    path_config: &PathConfig,
    input_path: Option<PathBuf>,
) -> Result<BenchmarkResults, String> {
    let size = path_config.circuit_size;

    if input_path.is_none() {
        let jwt_input = path_config.input_json("jwt");
        if !jwt_input.exists() {
            return Err(format!(
                "JWT inputs not found for size {size}:\n  {}\nRun: yarn generate:inputs --size {size}",
                jwt_input.display()
            ));
        }
        let show_input = path_config.input_json("show");
        if !show_input.exists() {
            return Err(format!(
                "Show inputs not found for size {size}:\n  {}\nRun: yarn generate:inputs --size {size}",
                show_input.display()
            ));
        }
    }

    let prepare_pk_path = path_config.key_path(PREPARE_PROVING_KEY);
    let prepare_vk_path = path_config.key_path(PREPARE_VERIFYING_KEY);
    let show_pk_path = path_config.key_path(SHOW_PROVING_KEY);
    let show_vk_path = path_config.key_path(SHOW_VERIFYING_KEY);

    if !prepare_pk_path.exists() || !prepare_vk_path.exists() {
        return Err(format!(
            "Prepare keys not found for size {size}.\n\
             Run:  cargo run --release -- prepare setup --size {size}"
        ));
    }
    if !show_pk_path.exists() || !show_vk_path.exists() {
        return Err(format!(
            "Show keys not found for size {size}.\n\
             Run:  cargo run --release -- show setup --size {size}"
        ));
    }

    let prepare_pk = load_proving_key(&prepare_pk_path)
        .map_err(|e| format!("Failed to load prepare proving key: {e}"))?;
    let prepare_vk = load_verifying_key(&prepare_vk_path)
        .map_err(|e| format!("Failed to load prepare verifying key: {e}"))?;
    let show_pk = load_proving_key(&show_pk_path)
        .map_err(|e| format!("Failed to load show proving key: {e}"))?;
    let show_vk = load_verifying_key(&show_vk_path)
        .map_err(|e| format!("Failed to load show verifying key: {e}"))?;

    info!("Generating shared blinds...");
    let t0 = Instant::now();
    generate_shared_blinds::<E>(path_config.artifact_path(SHARED_BLINDS), NUM_SHARED);
    let generate_blinds_ms = t0.elapsed().as_millis();
    println!("✓ Shared blinds generated: {} ms\n", generate_blinds_ms);

    info!("Proving Prepare circuit...");
    let t0 = Instant::now();
    let prepare_circuit = PrepareCircuit::new(path_config.clone(), input_path.clone());
    prove_circuit_with_pk(
        prepare_circuit,
        &prepare_pk,
        path_config.artifact_path(PREPARE_INSTANCE),
        path_config.artifact_path(PREPARE_WITNESS),
        path_config.artifact_path(PREPARE_PROOF),
    );
    let prove_prepare_ms = t0.elapsed().as_millis();
    println!("✓ Prepare proof generated: {} ms\n", prove_prepare_ms);

    let prepare_instance = load_instance(path_config.artifact_path(PREPARE_INSTANCE))
        .expect("load prepare instance failed");
    let prepare_witness = load_witness(path_config.artifact_path(PREPARE_WITNESS))
        .expect("load prepare witness failed");
    let shared_blinds = load_shared_blinds::<E>(path_config.artifact_path(SHARED_BLINDS))
        .expect("load shared_blinds failed");

    info!("Reblinding Prepare proof...");
    let t0 = Instant::now();
    reblind_with_loaded_data(
        &prepare_pk,
        prepare_instance,
        prepare_witness,
        &shared_blinds,
        path_config.artifact_path(PREPARE_INSTANCE),
        path_config.artifact_path(PREPARE_WITNESS),
        path_config.artifact_path(PREPARE_PROOF),
    );
    let reblind_prepare_ms = t0.elapsed().as_millis();
    println!("✓ Prepare proof reblinded: {} ms\n", reblind_prepare_ms);

    info!("Proving Show circuit...");
    let t0 = Instant::now();
    let show_circuit = ShowCircuit::new(path_config.clone(), None);
    prove_circuit_with_pk(
        show_circuit,
        &show_pk,
        path_config.artifact_path(SHOW_INSTANCE),
        path_config.artifact_path(SHOW_WITNESS),
        path_config.artifact_path(SHOW_PROOF),
    );
    let prove_show_ms = t0.elapsed().as_millis();
    println!("✓ Show proof generated: {} ms\n", prove_show_ms);

    let show_instance =
        load_instance(path_config.artifact_path(SHOW_INSTANCE)).expect("load show instance failed");
    let show_witness =
        load_witness(path_config.artifact_path(SHOW_WITNESS)).expect("load show witness failed");

    info!("Reblinding Show proof...");
    let t0 = Instant::now();
    reblind_with_loaded_data(
        &show_pk,
        show_instance,
        show_witness,
        &shared_blinds,
        path_config.artifact_path(SHOW_INSTANCE),
        path_config.artifact_path(SHOW_WITNESS),
        path_config.artifact_path(SHOW_PROOF),
    );
    let reblind_show_ms = t0.elapsed().as_millis();
    println!("✓ Show proof reblinded: {} ms\n", reblind_show_ms);

    let prepare_proof =
        load_proof(path_config.artifact_path(PREPARE_PROOF)).expect("load prepare proof failed");

    info!("Verifying Prepare proof...");
    let t0 = Instant::now();
    let prepare_public_values = verify_circuit_with_loaded_data(&prepare_proof, &prepare_vk);
    let verify_prepare_ms = t0.elapsed().as_millis();
    println!("✓ Prepare proof verified: {} ms", verify_prepare_ms);
    let jwt_layout = calculate_jwt_output_indices(size);
    print_public_statement(
        &prepare_public_values,
        jwt_layout.issuer_key_x_index,
        jwt_layout.decode_flags_range(),
        jwt_layout.claim_formats_range(),
    );

    let show_proof =
        load_proof(path_config.artifact_path(SHOW_PROOF)).expect("load show proof failed");

    info!("Verifying Show proof...");
    let t0 = Instant::now();
    let show_public_values = verify_circuit_with_loaded_data(&show_proof, &show_vk);
    let verify_show_ms = t0.elapsed().as_millis();
    println!("✓ Show proof verified: {} ms", verify_show_ms);
    if !show_public_values.is_empty() {
        let expression_result = show_public_values[0] == Field::ONE;
        println!("  expressionResult: {}\n", expression_result);
    }

    // Item 12: linkage. Verifying the two proofs separately is not enough — an
    // honest Prepare could be paired with an independently-forged Show over
    // unrelated claim values and a self-chosen device key. Require both to
    // commit to the same shared witness (comm_W_shared), read from the proofs.
    let prepare_shared = prepare_proof.comm_W_shared();
    let show_shared = show_proof.comm_W_shared();
    let linked =
        prepare_shared.is_some() && show_shared.is_some() && prepare_shared == show_shared;
    if linked {
        println!("✓ comm_W_shared linkage verified\n");
    } else {
        println!("✗ comm_W_shared linkage FAILED: Prepare and Show are not the same credential\n");
    }

    let prepare_proving_key_bytes =
        get_file_size(&path_config.key_path(PREPARE_PROVING_KEY).to_string_lossy());
    let prepare_verifying_key_bytes = get_file_size(
        &path_config
            .key_path(PREPARE_VERIFYING_KEY)
            .to_string_lossy(),
    );
    let show_proving_key_bytes =
        get_file_size(&path_config.key_path(SHOW_PROVING_KEY).to_string_lossy());
    let show_verifying_key_bytes =
        get_file_size(&path_config.key_path(SHOW_VERIFYING_KEY).to_string_lossy());
    let prepare_proof_bytes =
        get_file_size(&path_config.artifact_path(PREPARE_PROOF).to_string_lossy());
    let show_proof_bytes = get_file_size(&path_config.artifact_path(SHOW_PROOF).to_string_lossy());
    let prepare_witness_bytes =
        get_file_size(&path_config.artifact_path(PREPARE_WITNESS).to_string_lossy());
    let show_witness_bytes =
        get_file_size(&path_config.artifact_path(SHOW_WITNESS).to_string_lossy());

    Ok(BenchmarkResults {
        size,
        prepare_setup_ms: None,
        show_setup_ms: None,
        generate_blinds_ms,
        prove_prepare_ms,
        reblind_prepare_ms,
        prove_show_ms,
        reblind_show_ms,
        verify_prepare_ms,
        verify_show_ms,
        prepare_proving_key_bytes,
        prepare_verifying_key_bytes,
        show_proving_key_bytes,
        show_verifying_key_bytes,
        prepare_proof_bytes,
        show_proof_bytes,
        prepare_witness_bytes,
        show_witness_bytes,
    })
}

/// Prove + reblind + verify pipeline for the MDOC → Show flow.
fn run_mdoc_prove_pipeline(
    path_config: &PathConfig,
    mdoc_input: Option<PathBuf>,
) -> Result<BenchmarkResults, String> {
    let size = path_config.circuit_size;

    let show_mdoc_input = path_config
        .base_dir
        .join("../circom/inputs/show/mdoc.json");
    let resolved_mdoc_input = mdoc_input.unwrap_or_else(|| path_config.input_json("mdoc"));
    if !resolved_mdoc_input.exists() {
        return Err(format!(
            "MDOC inputs not found:\n  {}\nRun: yarn generate:inputs:mdoc",
            resolved_mdoc_input.display()
        ));
    }
    if !show_mdoc_input.exists() {
        return Err(format!(
            "Show inputs for mdoc flow not found:\n  {}\nRun: yarn generate:inputs:mdoc",
            show_mdoc_input.display()
        ));
    }

    let mdoc_pk_path = path_config.key_path(MDOC_PROVING_KEY);
    let mdoc_vk_path = path_config.key_path(MDOC_VERIFYING_KEY);
    let show_pk_path = path_config.key_path(SHOW_PROVING_KEY);
    let show_vk_path = path_config.key_path(SHOW_VERIFYING_KEY);

    if !mdoc_pk_path.exists() || !mdoc_vk_path.exists() {
        return Err("MDOC keys not found. Run: cargo run --release -- mdoc setup".into());
    }
    if !show_pk_path.exists() || !show_vk_path.exists() {
        return Err(format!(
            "Show keys not found for size {size}.\n\
             Run:  cargo run --release -- show setup --size {size}"
        ));
    }

    let mdoc_pk = load_proving_key(&mdoc_pk_path)
        .map_err(|e| format!("Failed to load mdoc proving key: {e}"))?;
    let mdoc_vk = load_verifying_key(&mdoc_vk_path)
        .map_err(|e| format!("Failed to load mdoc verifying key: {e}"))?;
    let show_pk = load_proving_key(&show_pk_path)
        .map_err(|e| format!("Failed to load show proving key: {e}"))?;
    let show_vk = load_verifying_key(&show_vk_path)
        .map_err(|e| format!("Failed to load show verifying key: {e}"))?;

    info!("Generating shared blinds...");
    let t0 = Instant::now();
    generate_shared_blinds::<E>(path_config.artifact_path(SHARED_BLINDS), NUM_SHARED);
    let generate_blinds_ms = t0.elapsed().as_millis();
    println!("✓ Shared blinds generated: {} ms\n", generate_blinds_ms);

    info!("Proving MDOC circuit...");
    let t0 = Instant::now();
    let mdoc_circuit = MdocCircuit::new(path_config.clone(), Some(resolved_mdoc_input.clone()));
    prove_circuit_with_pk(
        mdoc_circuit,
        &mdoc_pk,
        path_config.artifact_path(MDOC_INSTANCE),
        path_config.artifact_path(MDOC_WITNESS),
        path_config.artifact_path(MDOC_PROOF),
    );
    let prove_mdoc_ms = t0.elapsed().as_millis();
    println!("✓ MDOC proof generated: {} ms\n", prove_mdoc_ms);

    let mdoc_instance = load_instance(path_config.artifact_path(MDOC_INSTANCE))
        .expect("load mdoc instance failed");
    let mdoc_witness =
        load_witness(path_config.artifact_path(MDOC_WITNESS)).expect("load mdoc witness failed");
    let shared_blinds = load_shared_blinds::<E>(path_config.artifact_path(SHARED_BLINDS))
        .expect("load shared_blinds failed");

    info!("Reblinding MDOC proof...");
    let t0 = Instant::now();
    reblind_with_loaded_data(
        &mdoc_pk,
        mdoc_instance,
        mdoc_witness,
        &shared_blinds,
        path_config.artifact_path(MDOC_INSTANCE),
        path_config.artifact_path(MDOC_WITNESS),
        path_config.artifact_path(MDOC_PROOF),
    );
    let reblind_mdoc_ms = t0.elapsed().as_millis();
    println!("✓ MDOC proof reblinded: {} ms\n", reblind_mdoc_ms);

    info!("Proving Show circuit (mdoc flow)...");
    let t0 = Instant::now();
    let show_circuit = ShowCircuit::new(path_config.clone(), Some(show_mdoc_input.clone()));
    prove_circuit_with_pk(
        show_circuit,
        &show_pk,
        path_config.artifact_path(SHOW_INSTANCE),
        path_config.artifact_path(SHOW_WITNESS),
        path_config.artifact_path(SHOW_PROOF),
    );
    let prove_show_ms = t0.elapsed().as_millis();
    println!("✓ Show proof generated: {} ms\n", prove_show_ms);

    let show_instance =
        load_instance(path_config.artifact_path(SHOW_INSTANCE)).expect("load show instance failed");
    let show_witness =
        load_witness(path_config.artifact_path(SHOW_WITNESS)).expect("load show witness failed");

    info!("Reblinding Show proof...");
    let t0 = Instant::now();
    reblind_with_loaded_data(
        &show_pk,
        show_instance,
        show_witness,
        &shared_blinds,
        path_config.artifact_path(SHOW_INSTANCE),
        path_config.artifact_path(SHOW_WITNESS),
        path_config.artifact_path(SHOW_PROOF),
    );
    let reblind_show_ms = t0.elapsed().as_millis();
    println!("✓ Show proof reblinded: {} ms\n", reblind_show_ms);

    let mdoc_proof =
        load_proof(path_config.artifact_path(MDOC_PROOF)).expect("load mdoc proof failed");
    info!("Verifying MDOC proof...");
    let t0 = Instant::now();
    let mdoc_public_values = verify_circuit_with_loaded_data(&mdoc_proof, &mdoc_vk);
    let verify_mdoc_ms = t0.elapsed().as_millis();
    println!("✓ MDOC proof verified: {} ms", verify_mdoc_ms);
    let mdoc_layout =
        calculate_mdoc_output_indices(ecdsa_spartan2::circuits::mdoc_circuit::MDOC_MAX_CLAIMS);
    print_public_statement(
        &mdoc_public_values,
        mdoc_layout.issuer_key_x_index,
        mdoc_layout.value_types_range(),
        mdoc_layout.claim_flags_range(),
    );

    let show_proof =
        load_proof(path_config.artifact_path(SHOW_PROOF)).expect("load show proof failed");
    info!("Verifying Show proof...");
    let t0 = Instant::now();
    let show_public_values = verify_circuit_with_loaded_data(&show_proof, &show_vk);
    let verify_show_ms = t0.elapsed().as_millis();
    println!("✓ Show proof verified: {} ms", verify_show_ms);
    if !show_public_values.is_empty() {
        let expression_result = show_public_values[0] == Field::ONE;
        println!("  expressionResult: {}\n", expression_result);
    }

    Ok(BenchmarkResults {
        size,
        prepare_setup_ms: None,
        show_setup_ms: None,
        generate_blinds_ms,
        prove_prepare_ms: prove_mdoc_ms,
        reblind_prepare_ms: reblind_mdoc_ms,
        prove_show_ms,
        reblind_show_ms,
        verify_prepare_ms: verify_mdoc_ms,
        verify_show_ms,
        prepare_proving_key_bytes: get_file_size(&mdoc_pk_path.to_string_lossy()),
        prepare_verifying_key_bytes: get_file_size(&mdoc_vk_path.to_string_lossy()),
        show_proving_key_bytes: get_file_size(&show_pk_path.to_string_lossy()),
        show_verifying_key_bytes: get_file_size(&show_vk_path.to_string_lossy()),
        prepare_proof_bytes: get_file_size(
            &path_config.artifact_path(MDOC_PROOF).to_string_lossy(),
        ),
        show_proof_bytes: get_file_size(&path_config.artifact_path(SHOW_PROOF).to_string_lossy()),
        prepare_witness_bytes: get_file_size(
            &path_config.artifact_path(MDOC_WITNESS).to_string_lossy(),
        ),
        show_witness_bytes: get_file_size(
            &path_config.artifact_path(SHOW_WITNESS).to_string_lossy(),
        ),
    })
}

/// Full 9-step benchmark: setup → prove → reblind → verify.
fn run_complete_pipeline(path_config: PathConfig, input_path: Option<PathBuf>) -> BenchmarkResults {
    let size = path_config.circuit_size;

    println!("\n╔════════════════════════════════════════════════════╗");
    println!(
        "║  STARTING COMPLETE BENCHMARK PIPELINE  (size: {:>3})  ║",
        size
    );
    println!("╚════════════════════════════════════════════════════╝\n");

    info!("Step 1/9: Setting up Prepare circuit...");
    let prepare_circuit = PrepareCircuit::new(path_config.clone(), input_path.clone());
    let t0 = Instant::now();
    let (prepare_pk, prepare_vk) = setup_circuit_keys_no_save(prepare_circuit);
    let prepare_setup_ms = t0.elapsed().as_millis();
    println!("✓ Prepare setup completed: {} ms\n", prepare_setup_ms);

    if let Err(e) = save_keys(
        path_config.key_path(PREPARE_PROVING_KEY),
        path_config.key_path(PREPARE_VERIFYING_KEY),
        &prepare_pk,
        &prepare_vk,
    ) {
        eprintln!("Failed to save Prepare keys: {}", e);
        process::exit(1);
    }

    info!("Step 2/9: Setting up Show circuit...");
    let show_circuit = ShowCircuit::new(path_config.clone(), None);
    let t0 = Instant::now();
    let (show_pk, show_vk) = setup_circuit_keys_no_save(show_circuit);
    let show_setup_ms = t0.elapsed().as_millis();
    println!("✓ Show setup completed: {} ms\n", show_setup_ms);

    if let Err(e) = save_keys(
        path_config.key_path(SHOW_PROVING_KEY),
        path_config.key_path(SHOW_VERIFYING_KEY),
        &show_pk,
        &show_vk,
    ) {
        eprintln!("Failed to save Show keys: {}", e);
        process::exit(1);
    }

    let mut results = run_prove_pipeline(&path_config, input_path)
        .expect("prove pipeline failed after successful setup");

    results.prepare_setup_ms = Some(prepare_setup_ms);
    results.show_setup_ms = Some(show_setup_ms);
    results
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitKind {
    Prepare,
    Show,
    Mdoc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitAction {
    Run,
    Setup,
    Prove,
    Verify,
    Reblind,
    GenerateSharedBlinds,
    Benchmark,
}

#[derive(Debug, Default, Clone)]
struct CommandOptions {
    input: Option<PathBuf>,
    size: Option<CircuitSize>,
}

impl CommandOptions {
    fn path_config(&self) -> PathConfig {
        PathConfig::development_with_size(self.size.unwrap_or_default())
    }
}

#[derive(Debug, Clone)]
struct ParsedCommand {
    circuit: CircuitKind,
    action: CircuitAction,
    options: CommandOptions,
}

fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(true)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = args().collect();
    let command_args: &[String] = if args.len() > 1 { &args[1..] } else { &[] };

    if let Some(name @ ("setup-sha256" | "prove-sha256" | "verify-sha256")) =
        command_args.first().map(String::as_str)
    {
        let rest = &command_args[1..];
        let result = match name {
            "setup-sha256" if rest.is_empty() => Ok(setup_sha256()),
            "setup-sha256" => Err(format!("{name} takes no arguments")),
            "prove-sha256" => sha256_path_flag(rest, "--out").map(prove_sha256),
            _ => sha256_path_flag(rest, "--proof").map(verify_sha256),
        };
        if let Err(err) = result {
            eprintln!("Error: {err}");
            print_usage();
            process::exit(1);
        }
        return;
    }

    let command = match parse_command(command_args) {
        Ok(cmd) => cmd,
        Err(err) => {
            eprintln!("Error: {}", err);
            print_usage();
            process::exit(1);
        }
    };

    match command.circuit {
        CircuitKind::Prepare => execute_prepare(command.action, command.options),
        CircuitKind::Show => execute_show(command.action, command.options),
        CircuitKind::Mdoc => execute_mdoc(command.action, command.options),
    }
}

/// SHA-256 over the fixed 2 KB message, for the primitives benchmark. Files live
/// in this crate's `keys/` whatever the cwd (the host verifier reads them there),
/// without a size prefix because the circuit has one size.
fn sha256_keys_dir() -> PathBuf {
    PathConfig::new(env!("CARGO_MANIFEST_DIR"), false).keys_dir()
}

fn setup_sha256() {
    let keys_dir = sha256_keys_dir();
    setup_circuit_keys(
        Sha256Circuit::fixed(),
        keys_dir.join(SHA256_PROVING_KEY),
        keys_dir.join(SHA256_VERIFYING_KEY),
    );
}

/// `[flag PATH]` and nothing else.
fn sha256_path_flag(args: &[String], flag: &str) -> Result<Option<PathBuf>, String> {
    match args {
        [] => Ok(None),
        [f, path] if f == flag => Ok(Some(PathBuf::from(path))),
        _ => Err(format!("expected no arguments or `{flag} PATH`, got: {}", args.join(" "))),
    }
}

/// What the timed process does: load the proving key, prove in memory, write the
/// proof (`sha256_2048_proof.bin` in `out_dir`, default the keys dir). No
/// verifying key, no witness or instance file; `verify-sha256` checks the proof.
fn prove_sha256(out_dir: Option<PathBuf>) {
    let keys_dir = sha256_keys_dir();
    let pk = load_proving_key(keys_dir.join(SHA256_PROVING_KEY)).expect("load proving key failed");
    let (proof, _, _) = prove_circuit_in_memory(Sha256Circuit::fixed(), &pk).expect("prove failed");
    save_proof(out_dir.unwrap_or(keys_dir).join(SHA256_PROOF), &proof).expect("save proof failed");
}

/// Verifies the proof against the pinned verifying key and checks the public
/// values are the digest of the fixed message. Panics on failure.
fn verify_sha256(proof_path: Option<PathBuf>) {
    let keys_dir = sha256_keys_dir();
    let proof = load_proof(proof_path.unwrap_or_else(|| keys_dir.join(SHA256_PROOF)))
        .expect("load proof failed");
    let vk = load_verifying_key(keys_dir.join(SHA256_VERIFYING_KEY)).expect("load verifying key failed");
    let public_values = verify_circuit_with_loaded_data(&proof, &vk);
    assert_eq!(public_values, sha256_digest_bits(&sha256_fixed_message()));
    println!("PASS sha256 proof");
}

fn execute_prepare(action: CircuitAction, options: CommandOptions) {
    let path_config = options.path_config();

    match action {
        CircuitAction::Setup => {
            info!(input = ?options.input, size = %path_config.circuit_size, "Setting up keys for Prepare");
            let circuit = PrepareCircuit::new(path_config.clone(), options.input.clone());
            setup_circuit_keys(
                circuit,
                path_config.key_path(PREPARE_PROVING_KEY),
                path_config.key_path(PREPARE_VERIFYING_KEY),
            );
        }
        CircuitAction::Run => {
            let circuit = PrepareCircuit::new(path_config, options.input.clone());
            info!("Running Prepare circuit");
            run_circuit(circuit);
        }
        CircuitAction::Prove => {
            let circuit = PrepareCircuit::new(path_config.clone(), options.input.clone());
            info!("Proving Prepare circuit");
            prove_circuit(
                circuit,
                path_config.key_path(PREPARE_PROVING_KEY),
                path_config.artifact_path(PREPARE_INSTANCE),
                path_config.artifact_path(PREPARE_WITNESS),
                path_config.artifact_path(PREPARE_PROOF),
            );
        }
        CircuitAction::Verify => {
            info!("Verifying Prepare proof");
            let _public_values = verify_circuit(
                path_config.artifact_path(PREPARE_PROOF),
                path_config.key_path(PREPARE_VERIFYING_KEY),
            );
        }
        CircuitAction::Reblind => {
            info!("Reblinding Prepare proof");
            reblind(
                path_config.key_path(PREPARE_PROVING_KEY),
                path_config.artifact_path(PREPARE_INSTANCE),
                path_config.artifact_path(PREPARE_WITNESS),
                path_config.artifact_path(PREPARE_PROOF),
                path_config.artifact_path(SHARED_BLINDS),
            );
        }
        CircuitAction::GenerateSharedBlinds => {
            info!("Generating shared blinds");
            generate_shared_blinds::<E>(path_config.artifact_path(SHARED_BLINDS), NUM_SHARED);
        }
        CircuitAction::Benchmark => {
            let results = run_complete_pipeline(path_config, options.input);
            results.print_summary();
        }
    }
}

fn execute_show(action: CircuitAction, options: CommandOptions) {
    let path_config = options.path_config();

    match action {
        CircuitAction::Setup => {
            info!(size = %path_config.circuit_size, "Setting up keys for Show");
            let circuit = ShowCircuit::new(path_config.clone(), None);
            setup_circuit_keys(
                circuit,
                path_config.key_path(SHOW_PROVING_KEY),
                path_config.key_path(SHOW_VERIFYING_KEY),
            );
        }
        CircuitAction::Run => {
            let circuit = ShowCircuit::new(path_config, options.input.clone());
            info!("Running Show circuit");
            run_circuit(circuit);
        }
        CircuitAction::Prove => {
            let circuit = ShowCircuit::new(path_config.clone(), options.input.clone());
            info!("Proving Show circuit");
            prove_circuit(
                circuit,
                path_config.key_path(SHOW_PROVING_KEY),
                path_config.artifact_path(SHOW_INSTANCE),
                path_config.artifact_path(SHOW_WITNESS),
                path_config.artifact_path(SHOW_PROOF),
            );
        }
        CircuitAction::Verify => {
            info!("Verifying Show proof");
            let public_values = verify_circuit(
                path_config.artifact_path(SHOW_PROOF),
                path_config.key_path(SHOW_VERIFYING_KEY),
            );
            if !public_values.is_empty() {
                let expression_result = public_values[0] == Field::ONE;
                println!(
                    "expressionResult: {} (raw: {:?})",
                    expression_result, public_values[0]
                );
            }
        }
        CircuitAction::Reblind => {
            info!("Reblinding Show proof");
            reblind(
                path_config.key_path(SHOW_PROVING_KEY),
                path_config.artifact_path(SHOW_INSTANCE),
                path_config.artifact_path(SHOW_WITNESS),
                path_config.artifact_path(SHOW_PROOF),
                path_config.artifact_path(SHARED_BLINDS),
            );
        }
        CircuitAction::GenerateSharedBlinds => {
            eprintln!("Error: generate_shared_blinds is only supported for the Prepare circuit");
            process::exit(1);
        }
        CircuitAction::Benchmark => {
            let results = run_complete_pipeline(path_config, options.input);
            results.print_summary();
        }
    }
}

fn execute_mdoc(action: CircuitAction, options: CommandOptions) {
    let path_config = options.path_config();

    match action {
        CircuitAction::Setup => {
            info!(input = ?options.input, "Setting up keys for MDOC");
            let circuit = MdocCircuit::new(path_config.clone(), options.input.clone());
            setup_circuit_keys(
                circuit,
                path_config.key_path(MDOC_PROVING_KEY),
                path_config.key_path(MDOC_VERIFYING_KEY),
            );
        }
        CircuitAction::Run => {
            let circuit = MdocCircuit::new(path_config, options.input.clone());
            info!("Running MDOC circuit");
            run_circuit(circuit);
        }
        CircuitAction::Prove => {
            let circuit = MdocCircuit::new(path_config.clone(), options.input.clone());
            info!("Proving MDOC circuit");
            prove_circuit(
                circuit,
                path_config.key_path(MDOC_PROVING_KEY),
                path_config.artifact_path(MDOC_INSTANCE),
                path_config.artifact_path(MDOC_WITNESS),
                path_config.artifact_path(MDOC_PROOF),
            );
        }
        CircuitAction::Verify => {
            info!("Verifying MDOC proof");
            let _public_values = verify_circuit(
                path_config.artifact_path(MDOC_PROOF),
                path_config.key_path(MDOC_VERIFYING_KEY),
            );
        }
        CircuitAction::Reblind => {
            info!("Reblinding MDOC proof");
            reblind(
                path_config.key_path(MDOC_PROVING_KEY),
                path_config.artifact_path(MDOC_INSTANCE),
                path_config.artifact_path(MDOC_WITNESS),
                path_config.artifact_path(MDOC_PROOF),
                path_config.artifact_path(SHARED_BLINDS),
            );
        }
        CircuitAction::GenerateSharedBlinds => {
            info!("Generating shared blinds (mdoc)");
            generate_shared_blinds::<E>(path_config.artifact_path(SHARED_BLINDS), NUM_SHARED);
        }
        CircuitAction::Benchmark => match run_mdoc_prove_pipeline(&path_config, options.input) {
            Ok(results) => results.print_summary(),
            Err(e) => {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
        },
    }
}

fn parse_command(args: &[String]) -> Result<ParsedCommand, String> {
    if args.is_empty() {
        return Err("No command provided".into());
    }

    match args[0].as_str() {
        "-h" | "--help" => {
            print_usage();
            process::exit(0);
        }
        "prepare" => parse_circuit_command(CircuitKind::Prepare, &args[1..]),
        "show" => parse_circuit_command(CircuitKind::Show, &args[1..]),
        "mdoc" => parse_circuit_command(CircuitKind::Mdoc, &args[1..]),
        "benchmark" => Ok(ParsedCommand {
            circuit: CircuitKind::Prepare,
            action: CircuitAction::Benchmark,
            options: parse_options(&args[1..])?,
        }),

        "benchmark-all" => {
            if let Some(unknown) = args
                .get(1)
                .filter(|a| !a.starts_with('-') || *a != "--help")
            {
                if unknown != "--help" && unknown != "-h" {
                    return Err(format!("benchmark-all takes no options, got: {}", unknown));
                }
            }

            let mut all_results: Vec<BenchmarkResults> = Vec::new();

            println!("\n╔════════════════════════════════════════════════════╗");
            println!("║      BENCHMARK-ALL: prove + reblind + verify        ║");
            println!("╚════════════════════════════════════════════════════╝\n");

            for size in CircuitSize::ALL {
                let pc = PathConfig::development_with_size(size);
                println!("─── Size: {} ─────────────────────────────────────", size);
                match run_prove_pipeline(&pc, None) {
                    Ok(r) => {
                        r.print_summary();
                        all_results.push(r);
                    }
                    Err(e) => {
                        eprintln!("  ✗ Skipping size {}: {}\n", size, e);
                    }
                }
            }

            if all_results.len() > 1 {
                println!("═══ COMPARISON TABLE ══════════════════════════════");
                print_comparison_table(&all_results);
            }

            process::exit(0);
        }

        "setup_prepare" => Ok(ParsedCommand {
            circuit: CircuitKind::Prepare,
            action: CircuitAction::Setup,
            options: parse_options(&args[1..])?,
        }),
        "setup_show" => Ok(ParsedCommand {
            circuit: CircuitKind::Show,
            action: CircuitAction::Setup,
            options: parse_options(&args[1..])?,
        }),
        "prove_prepare" => Ok(ParsedCommand {
            circuit: CircuitKind::Prepare,
            action: CircuitAction::Prove,
            options: parse_options(&args[1..])?,
        }),
        "prove_show" => Ok(ParsedCommand {
            circuit: CircuitKind::Show,
            action: CircuitAction::Prove,
            options: parse_options(&args[1..])?,
        }),
        "verify_prepare" => Ok(ParsedCommand {
            circuit: CircuitKind::Prepare,
            action: CircuitAction::Verify,
            options: parse_options_size_only(&args[1..])?,
        }),
        "verify_show" => Ok(ParsedCommand {
            circuit: CircuitKind::Show,
            action: CircuitAction::Verify,
            options: parse_options_size_only(&args[1..])?,
        }),
        "reblind_prepare" => Ok(ParsedCommand {
            circuit: CircuitKind::Prepare,
            action: CircuitAction::Reblind,
            options: parse_options_size_only(&args[1..])?,
        }),
        "reblind_show" => Ok(ParsedCommand {
            circuit: CircuitKind::Show,
            action: CircuitAction::Reblind,
            options: parse_options_size_only(&args[1..])?,
        }),
        "generate_shared_blinds" => Ok(ParsedCommand {
            circuit: CircuitKind::Prepare,
            action: CircuitAction::GenerateSharedBlinds,
            options: parse_options_size_only(&args[1..])?,
        }),
        other => Err(format!("Unknown command '{other}'")),
    }
}

fn parse_circuit_command(circuit: CircuitKind, tail: &[String]) -> Result<ParsedCommand, String> {
    if tail.is_empty() {
        return Ok(ParsedCommand {
            circuit,
            action: CircuitAction::Run,
            options: CommandOptions::default(),
        });
    }

    let first = &tail[0];
    let (action, option_start) = match first.as_str() {
        "run"                   => (CircuitAction::Run, 1),
        "setup"                 => (CircuitAction::Setup, 1),
        "prove"                 => (CircuitAction::Prove, 1),
        "verify"                => (CircuitAction::Verify, 1),
        "reblind"               => (CircuitAction::Reblind, 1),
        "generate_shared_blinds"=> (CircuitAction::GenerateSharedBlinds, 1),
        "benchmark"             => (CircuitAction::Benchmark, 1),
        s if s.starts_with('-') => (CircuitAction::Run, 0),
        other => {
            return Err(format!(
                "Unknown action '{other}' for {:?}. Expected: run|setup|prove|verify|reblind|generate_shared_blinds|benchmark.",
                circuit
            ))
        }
    };

    if action == CircuitAction::GenerateSharedBlinds && circuit != CircuitKind::Prepare {
        return Err("generate_shared_blinds is only supported for the Prepare circuit".into());
    }

    let options_slice = &tail[option_start..];
    let options = match action {
        CircuitAction::Run
        | CircuitAction::Prove
        | CircuitAction::Setup
        | CircuitAction::Benchmark => parse_options(options_slice)?,
        CircuitAction::Verify | CircuitAction::Reblind | CircuitAction::GenerateSharedBlinds => {
            parse_options_size_only(options_slice)?
        }
    };

    Ok(ParsedCommand {
        circuit,
        action,
        options,
    })
}

fn parse_options(args: &[String]) -> Result<CommandOptions, String> {
    let mut opts = CommandOptions::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--input" | "-i" => {
                i += 1;
                opts.input = Some(PathBuf::from(
                    args.get(i).ok_or("Missing value for --input")?,
                ));
            }
            "--size" | "-s" => {
                i += 1;
                opts.size = Some(
                    args.get(i)
                        .ok_or("Missing value for --size")?
                        .parse::<CircuitSize>()
                        .map_err(|e| format!("Invalid --size: {e}"))?,
                );
            }
            s if s.starts_with("--input=") => {
                let v = &s["--input=".len()..];
                if v.is_empty() {
                    return Err("Missing value for --input".into());
                }
                opts.input = Some(PathBuf::from(v));
            }
            s if s.starts_with("--size=") => {
                let v = &s["--size=".len()..];
                opts.size = Some(
                    v.parse::<CircuitSize>()
                        .map_err(|e| format!("Invalid --size: {e}"))?,
                );
            }
            "--help" | "-h" => {
                print_usage();
                process::exit(0);
            }
            other => return Err(format!("Unknown option '{other}'")),
        }
        i += 1;
    }
    Ok(opts)
}

fn parse_options_size_only(args: &[String]) -> Result<CommandOptions, String> {
    let mut opts = CommandOptions::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--size" | "-s" => {
                i += 1;
                opts.size = Some(
                    args.get(i)
                        .ok_or("Missing value for --size")?
                        .parse::<CircuitSize>()
                        .map_err(|e| format!("Invalid --size: {e}"))?,
                );
            }
            s if s.starts_with("--size=") => {
                let v = &s["--size=".len()..];
                opts.size = Some(
                    v.parse::<CircuitSize>()
                        .map_err(|e| format!("Invalid --size: {e}"))?,
                );
            }
            "--help" | "-h" => {
                print_usage();
                process::exit(0);
            }
            other => return Err(format!("Unknown option '{other}'")),
        }
        i += 1;
    }
    Ok(opts)
}

fn print_usage() {
    eprintln!(
        "Usage:
  ecdsa-spartan2 <prepare|show> [run|setup|prove|verify|reblind|benchmark] [options]
  ecdsa-spartan2 benchmark      [options]
  ecdsa-spartan2 benchmark-all
  ecdsa-spartan2 setup-sha256
  ecdsa-spartan2 prove-sha256 [--out DIR]
  ecdsa-spartan2 verify-sha256 [--proof PATH]

Commands:
  benchmark         Full pipeline (setup+prove+reblind+verify) for one size
  benchmark-all     Prove+reblind+verify across ALL compiled sizes, print comparison table
  prepare <action>  Run action on Prepare circuit
  show    <action>  Run action on Show circuit
  setup-sha256      Generate keys/sha256_2048_proving.key and _verifying.key (SHA-256 of a fixed 2 KB message)
  prove-sha256      Prove it in memory and write sha256_2048_proof.bin to DIR (default keys/)
  verify-sha256     Verify a proof (default keys/sha256_2048_proof.bin) and its digest

Actions:
  run               Run circuit (setup, prove, verify)
  setup             Generate proving and verifying keys
  prove             Generate proof
  verify            Verify proof
  reblind           Reblind proof
  benchmark         Full benchmark pipeline for this circuit

Options:
  --size, -s <sz>   Circuit size: 1k | 2k | 4k | 8k  (default: 1k)
  --input, -i <p>   Override JWT input JSON path (prepare run/prove/setup/benchmark)

Typical workflow:
  # 1. Compile circuits (Circom side)
  cd ../circom && yarn compile:all

  # 2. Generate inputs for each size
  yarn generate:inputs --all

  # 3. Generate setup keys (one-time, slow)
  cargo run --release -- prepare setup --size 1k
  cargo run --release -- show    setup --size 1k
  # repeat for 2k, 4k, 8k

  # 4. Benchmark all sizes (fast: prove+reblind+verify only)
  cargo run --release -- benchmark-all

  # 5. Full single-size benchmark (includes setup timing)
  cargo run --release -- benchmark --size 2k

  # 6. SHA-256 primitive (no options; files go to this crate's keys/)
  cargo run --release -- setup-sha256
  cargo run --release -- prove-sha256 [--out DIR]
  cargo run --release -- verify-sha256 [--proof PATH]

Legacy commands: prove_prepare, prove_show, setup_prepare, setup_show,
verify_prepare, verify_show, reblind_prepare, reblind_show, generate_shared_blinds"
    );
}

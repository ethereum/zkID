//! CLI for running the Spartan-2 split RS256 circuits.
//!
//! The monolith RS256 circuit has been split into two stages:
//! - **cert-chain**: Certificate chain verification (Circuit A)
//! - **user-sig**: User signature verification (Circuit B)
//!
//!   | Command       | Feature flag        | Key size | CA             |
//!   |---------------|---------------------|----------|----------------|
//!   | cert-chain    | `cert_chain_rs2048` | RSA-2048 | MOICA-G2       |
//!   | cert-chain -4 | `cert_chain_rs4096` | RSA-4096 | 4096-bit CA    |
//!   | user-sig    | `user_sig_rs2048` | RSA-2048 | (user key)     |
//!
//! # Generate split circuit inputs
//!
//!   cargo run --release -- generate-split-input
//!   cargo run --release -- generate-split-input --cert-chain-4096
//!
//! # Setup / Prove / Verify  (cert-chain, RSA-2048)
//!
//!   cargo run --release --features cert_chain_rs2048 -- cert-chain setup
//!   cargo run --release --features cert_chain_rs2048 -- cert-chain prove --input ../circom/inputs/cert_chain_rs2048/input.json
//!   cargo run --release --features cert_chain_rs2048 -- cert-chain verify
//!
//! # Setup / Prove / Verify  (user-sig)
//!
//!   cargo run --release --features user_sig_rs2048 -- user-sig setup
//!   cargo run --release --features user_sig_rs2048 -- user-sig prove --input ../circom/inputs/user_sig_rs2048/input.json
//!   cargo run --release --features user_sig_rs2048 -- user-sig verify
//!
//! # Link-verify  (check pk_commit equality across proofs)
//!
//!   cargo run --release -- link-verify
//!   cargo run --release -- link-verify --cert-chain-4096

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use ecdsa_spartan2::{
    generate_split_inputs, load_proof, prove_circuit, prove_circuit_with_pk, run_circuit,
    save_keys, serial_bytes_to_hex_trimmed, setup_circuit_keys, setup_circuit_keys_no_save,
    verify_circuit, verify_circuit_with_loaded_data, CertChainCircuit, CertChainRs4096Circuit,
    CertChainRsa2048, CertChainRsa4096, UserSigRsa2048, PathConfig, RsaKeySize,
    Sha256RsaCircuit, APP_ID_LEN, MAX_CERT_CHAIN_LENGTH,
};
use std::{
    env::args,
    fs,
    path::{Path, PathBuf},
    process,
};
use web_time::Instant;
use num_bigint::BigUint;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

fn get_file_size(path: &Path) -> u64 {
    fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitAction {
    Run,
    Setup,
    Prove,
    Verify,
    Benchmark,
}

#[derive(Debug, Default, Clone)]
struct CommandOptions {
    input: Option<PathBuf>,
    /// Use RSA-4096 (4096-bit issuer CA) circuit instead of RSA-2048.
    rs4096: bool,
}

#[derive(Debug, Clone)]
struct ParsedCommand {
    action: CircuitAction,
    options: CommandOptions,
}

/// Require the next positional value for a flag, or exit with an error.
fn require_arg(args: &[String], index: &mut usize, flag: &str) -> String {
    *index += 1;
    args.get(*index).cloned().unwrap_or_else(|| {
        eprintln!("Missing value for {}", flag);
        process::exit(1);
    })
}

/// `generate-split-input` CLI: fixture load -> optional SMT fetch -> write two JSON files.
fn run_generate_split_input(command_args: &[String]) -> ! {
    let mut rs4096 = false;
    let mut smt_server: Option<String> = None;
    let mut issuer = "g2".to_string();
    let mut pin: Option<String> = None;
    let mut hipki_server = ecdsa_spartan2::hipki_client::default_server_url().to_string();
    let mut challenge_server = ecdsa_spartan2::challenge_client::default_server_url().to_string();
    let mut cert_chain_output = "../circom/inputs/cert_chain_rs2048/input.json".to_string();
    let mut user_sig_output = "../circom/inputs/user_sig_rs2048/input.json".to_string();
    let mut pk_blind_override: Option<String> = None;

    let mut i = 1;
    while i < command_args.len() {
        match command_args[i].as_str() {
            "--cert-chain-4096" | "-4" => {
                rs4096 = true;
                cert_chain_output = "../circom/inputs/cert_chain_rs4096/input.json".to_string();
                user_sig_output =
                    "../circom/inputs/user_sig_rs2048_chain_rs4096/input.json".to_string();
                issuer = "g3".to_string();
            }
            "--smt-server" => smt_server = Some(require_arg(command_args, &mut i, "--smt-server")),
            "--issuer" => issuer = require_arg(command_args, &mut i, "--issuer"),
            "--pin" => pin = Some(require_arg(command_args, &mut i, "--pin")),
            "--hipki-server" => hipki_server = require_arg(command_args, &mut i, "--hipki-server"),
            "--challenge-server" => {
                challenge_server = require_arg(command_args, &mut i, "--challenge-server")
            }
            "--pk-blind" => {
                let raw = require_arg(command_args, &mut i, "--pk-blind");
                let parsed = BigUint::parse_bytes(raw.as_bytes(), 10).unwrap_or_else(|| {
                    eprintln!("Error: --pk-blind must be a non-negative decimal integer");
                    process::exit(1);
                });
                if parsed.bits() > 248 {
                    eprintln!("Error: --pk-blind must be < 2^248 (got {} bits)", parsed.bits());
                    process::exit(1);
                }
                pk_blind_override = Some(raw);
            }
            _ => {}
        }
        i += 1;
    }

    let (k_issuer, k_user) = if rs4096 { (34, 17) } else { (17, 17) };
    let max_cert_length = MAX_CERT_CHAIN_LENGTH;

    let (user_cert, user_sig_b64, issuer_cert, serial_hex, app_id_bytes, challenge) = if let Some(ref pin) = pin {
        info!(server = %challenge_server, "Fetching challenge from verifier");
        let challenge_resp = ecdsa_spartan2::challenge_client::create_challenge(&challenge_server)
            .unwrap_or_else(|e| {
                eprintln!("Failed to fetch challenge from {}: {}", challenge_server, e);
                process::exit(1);
            });
        info!(
            challenge = %challenge_resp.challenge,
            expires_at = %challenge_resp.expires_at,
            "Challenge received"
        );
        let app_id_str = challenge_resp.app_id;
        let app_id_bytes = app_id_str.as_bytes().to_vec();
        if app_id_bytes.len() != APP_ID_LEN {
            eprintln!(
                "Verifier app_id is {} bytes, expected {} (got {:?})",
                app_id_bytes.len(),
                APP_ID_LEN,
                app_id_str,
            );
            process::exit(1);
        }

        info!(server = %hipki_server, "Fetching certificate chain from HiPKI");
        let pkcs11info = ecdsa_spartan2::hipki_client::fetch_pkcs11info(&hipki_server)
            .unwrap_or_else(|e| {
                eprintln!("Failed to fetch pkcs11info from {}: {}", hipki_server, e);
                process::exit(1);
            });
        let issuer_cert = CertChainCircuit::extract_issuer_cert(&pkcs11info)
            .unwrap_or_else(|e| {
                eprintln!("Failed to extract issuer cert: {}", e);
                process::exit(1);
            });

        info!(app_id = %app_id_str, "Signing app_id via HiPKI card");
        let sign_response = ecdsa_spartan2::hipki_client::sign_tbs(&hipki_server, &app_id_str, pin)
            .unwrap_or_else(|e| {
                eprintln!("Failed to sign via HiPKI: {}", e);
                process::exit(1);
            });
        let user_cert = CertChainCircuit::generate_user_cert_from_certb64(&sign_response.certb64)
            .unwrap_or_else(|e| {
                eprintln!("Failed to parse user cert from card response: {}", e);
                process::exit(1);
            });
        let serial_hex = serial_bytes_to_hex_trimmed(
            user_cert.tbs_certificate.serial_number.as_bytes(),
        );

        info!(
            challenge = %challenge_resp.challenge,
            serial = %serial_hex,
            "Live input ready — save challenge for /link-verify"
        );

        (
            user_cert,
            sign_response.signature,
            issuer_cert,
            serial_hex,
            app_id_bytes,
            challenge_resp.challenge,
        )
    } else if rs4096 {
        let response_path = Path::new("tests/testdata/rs4096_response_sign.json");
        let issuer_cert = CertChainRs4096Circuit::fetch_cert_from_file("tests/testdata/test_ca_rs4096.der")
            .expect("Failed to load RS4096 test CA cert");
        let response_str =
            fs::read_to_string(response_path).expect("Failed to read RS4096 sign response");
        let response: ecdsa_spartan2::circuits::types::Rs4096SignResponse =
            serde_json::from_str(&response_str).expect("Failed to parse RS4096 response");
        let user_cert = CertChainRs4096Circuit::generate_user_cert_from_certb64(&response.result.cert)
            .expect("Failed to parse user cert");
        let serial_hex = serial_bytes_to_hex_trimmed(
            user_cert.tbs_certificate.serial_number.as_bytes(),
        );
        (
            user_cert,
            response.result.signed_response,
            issuer_cert,
            serial_hex,
            ecdsa_spartan2::DEFAULT_TBS.to_vec(),
            ecdsa_spartan2::DEFAULT_CHALLENGE.to_string(),
        )
    } else {
        let response_path = Path::new("tests/testdata/response_sign_test.json");
        let pkcs11_path = Path::new("tests/testdata/pkcs11info_test.json");
        let pkcs11_str = fs::read_to_string(pkcs11_path).expect("Failed to read pkcs11 response");
        let pkcs11: ecdsa_spartan2::circuits::types::Pkcs11InfoResponse =
            serde_json::from_str(&pkcs11_str).expect("Failed to parse pkcs11 response");
        let issuer_cert =
            CertChainCircuit::extract_issuer_cert(&pkcs11).expect("Failed to extract issuer cert");
        let response_str =
            fs::read_to_string(response_path).expect("Failed to read sign response");
        let response: ecdsa_spartan2::circuits::types::CardSignResponse =
            serde_json::from_str(&response_str).expect("Failed to parse sign response");
        let user_cert = CertChainCircuit::generate_user_cert_from_certb64(&response.certb64)
            .expect("Failed to parse user cert");
        let serial_hex = serial_bytes_to_hex_trimmed(
            user_cert.tbs_certificate.serial_number.as_bytes(),
        );
        (
            user_cert,
            response.signature,
            issuer_cert,
            serial_hex,
            ecdsa_spartan2::DEFAULT_TBS.to_vec(),
            ecdsa_spartan2::DEFAULT_CHALLENGE.to_string(),
        )
    };

    let smt_inputs = smt_server.as_ref().map(|url| {
        ecdsa_spartan2::smt_client::fetch_smt_proof(url, &issuer, &serial_hex, 128)
            .expect("Failed to fetch SMT proof")
    });

    let from_override = pk_blind_override.is_some();
    let pk_blind = pk_blind_override.unwrap_or_else(ecdsa_spartan2::random_pk_blind);
    let prefix = &pk_blind[..pk_blind.len().min(8)];
    if from_override {
        warn!(pk_blind_prefix = prefix, "Using pkBlind from --pk-blind override — only safe for fixture/test runs; reusing across submissions defeats hiding");
    } else {
        info!(pk_blind_prefix = prefix, "Sampled pkBlind");
    }

    // Live runs prove validity at the current time; fixture runs use a fixed
    // time so the committed input JSONs stay deterministic.
    let current_time = if pin.is_some() {
        zkid_input_builder::current_time_utc()
    } else {
        ecdsa_spartan2::DEFAULT_CURRENT_TIME.to_string()
    };

    info!("Generating split inputs (cert_chain + user_sig)...");
    let (cert_chain_json, user_sig_json) = generate_split_inputs(
        &user_cert,
        &issuer_cert,
        &user_sig_b64,
        &app_id_bytes,
        &serial_hex,
        smt_inputs.as_ref(),
        k_issuer,
        k_user,
        max_cert_length,
        &pk_blind,
        &challenge,
        &current_time,
    )
    .unwrap_or_else(|e| {
        eprintln!("Error generating split inputs: {}", e);
        process::exit(1);
    });

    for (path, json) in [
        (&cert_chain_output, &cert_chain_json),
        (&user_sig_output, &user_sig_json),
    ] {
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent).ok();
        }
        fs::write(path, serde_json::to_string_pretty(json).unwrap()).unwrap_or_else(|e| {
            eprintln!("Failed to write {}: {}", path, e);
            process::exit(1);
        });
        info!(path = %path, "Written split input JSON");
    }
    process::exit(0);
}

/// Verify both proofs and check `pk_commit_A == pk_commit_B` to bind them to
/// the same user key.
///
/// CertChain public values: [pk_commit, issuer_modulus..., smtRoot]
/// UserSig public values: [pk_commit, nullifier, app_id_bytes[31]]
fn run_link_verify(command_args: &[String]) -> ! {
    let rs4096 = command_args.contains(&"--cert-chain-4096".to_string())
        || command_args.contains(&"-4".to_string());
    let path_config = PathConfig::development();

    let (cc_proof_file, cc_vk_file) = if rs4096 {
        (CertChainRsa4096::PROOF, CertChainRsa4096::VERIFYING_KEY)
    } else {
        (CertChainRsa2048::PROOF, CertChainRsa2048::VERIFYING_KEY)
    };
    info!("Verifying cert-chain proof...");
    let cc_public_values = verify_circuit(
        path_config.artifact_path(cc_proof_file),
        path_config.key_path(cc_vk_file),
    );

    info!("Verifying user-sig proof...");
    let ds_public_values = verify_circuit(
        path_config.artifact_path(UserSigRsa2048::PROOF),
        path_config.key_path(UserSigRsa2048::VERIFYING_KEY),
    );

    let pk_commit_a = &cc_public_values[0];
    let pk_commit_b = &ds_public_values[0];
    let nullifier = &ds_public_values[1];
    let app_id_packed = &ds_public_values[2];
    let challenge = &ds_public_values[3];

    use ff::PrimeField;
    use subtle::ConstantTimeEq;
    let commits_match: bool = pk_commit_a
        .to_repr()
        .as_ref()
        .ct_eq(pk_commit_b.to_repr().as_ref())
        .into();
    if commits_match {
        let bytes = app_id_packed.to_repr();
        let app_id_hex: String = bytes.as_ref()[..31]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        info!(
            pk_commit = ?pk_commit_a,
            nullifier = ?nullifier,
            app_id = %app_id_hex,
            challenge = ?challenge,
            "Link verification PASSED: pk_commit_A == pk_commit_B"
        );
        process::exit(0);
    } else {
        eprintln!(
            "Link verification FAILED!\n  pk_commit_A (cert-chain): {:?}\n  pk_commit_B (user-sig): {:?}",
            pk_commit_a, pk_commit_b
        );
        process::exit(1);
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(true)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = args().collect();
    let command_args: &[String] = if args.len() > 1 { &args[1..] } else { &[] };

    if command_args.first().map(|s| s.as_str()) == Some("generate-split-input") {
        run_generate_split_input(command_args);
    }

    if command_args.first().map(|s| s.as_str()) == Some("link-verify") {
        run_link_verify(command_args);
    }

    let command = match parse_command(command_args) {
        Ok(cmd) => cmd,
        Err(err) => {
            eprintln!("Error: {}", err);
            print_usage();
            process::exit(1);
        }
    };

    let top_command = &command_args[0];
    match top_command.as_str() {
        "cert-chain" => execute_cert_chain(command.action, command.options),
        "user-sig" => execute_user_sig(command.action, command.options),
        _ => {
            eprintln!("Unknown command '{}'. Use cert-chain or user-sig.", top_command);
            print_usage();
            process::exit(1);
        }
    }
}

/// Execute cert-chain (Circuit A) commands — dispatch by `--cert-chain-4096` flag.
fn execute_cert_chain(action: CircuitAction, options: CommandOptions) {
    if options.rs4096 {
        if !cfg!(feature = "cert_chain_rs4096") {
            eprintln!(
                "Error: --cert-chain-4096 requires the `cert_chain_rs4096` feature. \
                 Rebuild with --features cert_chain_rs4096"
            );
            process::exit(1);
        }
        execute_rs256_for::<CertChainRsa4096>(action, options);
        return;
    }
    if !cfg!(feature = "cert_chain_rs2048") {
        eprintln!(
            "Error: cert-chain commands require the `cert_chain_rs2048` feature. \
             Rebuild with --features cert_chain_rs2048"
        );
        process::exit(1);
    }
    execute_rs256_for::<CertChainRsa2048>(action, options);
}

/// Execute user-sig (Circuit B) commands — always RSA-2048.
fn execute_user_sig(action: CircuitAction, options: CommandOptions) {
    if !cfg!(feature = "user_sig_rs2048") {
        eprintln!(
            "Error: user-sig commands require the `user_sig_rs2048` feature. \
             Rebuild with --features user_sig_rs2048"
        );
        process::exit(1);
    }
    execute_rs256_for::<UserSigRsa2048>(action, options);
}

/// Generic execute — works for any RSA key size.
fn execute_rs256_for<T: RsaKeySize>(action: CircuitAction, options: CommandOptions) {
    let path_config = PathConfig::development();

    match action {
        CircuitAction::Setup => {
            info!(circuit = T::CIRCUIT_NAME, "Setting up Spartan-2 keys");
            let circuit = Sha256RsaCircuit::<T>::new(path_config.clone(), None);
            setup_circuit_keys(
                circuit,
                path_config.key_path(T::PROVING_KEY),
                path_config.key_path(T::VERIFYING_KEY),
            );
        }
        CircuitAction::Run => {
            info!(circuit = T::CIRCUIT_NAME, "Running circuit with ZK-Spartan");
            let circuit = Sha256RsaCircuit::<T>::new(path_config, options.input);
            run_circuit(circuit);
        }
        CircuitAction::Prove => {
            info!(circuit = T::CIRCUIT_NAME, "Proving circuit with ZK-Spartan");
            let circuit = Sha256RsaCircuit::<T>::new(path_config.clone(), options.input);
            prove_circuit(
                circuit,
                path_config.key_path(T::PROVING_KEY),
                path_config.artifact_path(T::INSTANCE),
                path_config.artifact_path(T::WITNESS),
                path_config.artifact_path(T::PROOF),
            );
        }
        CircuitAction::Verify => {
            info!(circuit = T::CIRCUIT_NAME, "Verifying proof with ZK-Spartan");
            verify_circuit(
                path_config.artifact_path(T::PROOF),
                path_config.key_path(T::VERIFYING_KEY),
            );
        }
        CircuitAction::Benchmark => {
            info!(circuit = T::CIRCUIT_NAME, "Running benchmark pipeline");
            run_rs256_benchmark_for::<T>(options.input);
        }
    }
}

/// Run benchmark for a specific RSA key-size circuit.
fn run_rs256_benchmark_for<T: RsaKeySize>(input_path: Option<PathBuf>) {
    let path_config = PathConfig::development();

    println!("\n╔════════════════════════════════════════════════╗");
    println!(
        "║  {} BENCHMARK PIPELINE  ║",
        T::CIRCUIT_NAME.to_uppercase()
    );
    println!("╚════════════════════════════════════════════════╝\n");

    // Step 0: Pre-generate witness while memory is clean
    let circuit = Sha256RsaCircuit::<T>::new(path_config.clone(), input_path.clone());
    info!("Pre-generating witness (before setup allocates keys)...");
    let t_witness = Instant::now();
    circuit
        .warm_witness_cache()
        .expect("witness generation failed");
    let witness_gen_ms = t_witness.elapsed().as_millis();
    println!("✓ Witness cached: {} ms\n", witness_gen_ms);

    info!("Step 1/3: Setting up {} circuit...", T::CIRCUIT_NAME);
    let t0 = Instant::now();
    let (pk, vk) = setup_circuit_keys_no_save(circuit.clone());
    let setup_ms = t0.elapsed().as_millis();
    println!("✓ Setup completed: {} ms\n", setup_ms);

    // Save keys
    if let Err(e) = save_keys(
        path_config.key_path(T::PROVING_KEY),
        path_config.key_path(T::VERIFYING_KEY),
        &pk,
        &vk,
    ) {
        eprintln!("Failed to save {} keys: {}", T::CIRCUIT_NAME, e);
        std::process::exit(1);
    }

    // Step 2: Prove
    info!("Step 2/3: Proving {} circuit...", T::CIRCUIT_NAME);
    let t0 = Instant::now();
    prove_circuit_with_pk(
        circuit,
        &pk,
        path_config.artifact_path(T::INSTANCE),
        path_config.artifact_path(T::WITNESS),
        path_config.artifact_path(T::PROOF),
    );
    let prove_ms = t0.elapsed().as_millis();
    println!("✓ Proof generated: {} ms\n", prove_ms);

    // Step 3: Verify
    info!("Step 3/3: Verifying {} proof...", T::CIRCUIT_NAME);
    let proof = load_proof(path_config.artifact_path(T::PROOF)).expect("load proof failed");
    let t0 = Instant::now();
    verify_circuit_with_loaded_data(&proof, &vk);
    let verify_ms = t0.elapsed().as_millis();
    println!("✓ Proof verified: {} ms\n", verify_ms);

    // Measure sizes
    let pk_bytes = get_file_size(path_config.key_path(T::PROVING_KEY).as_path());
    let vk_bytes = get_file_size(path_config.key_path(T::VERIFYING_KEY).as_path());
    let proof_bytes = get_file_size(path_config.artifact_path(T::PROOF).as_path());
    let witness_bytes = get_file_size(path_config.artifact_path(T::WITNESS).as_path());

    println!("\n╔════════════════════════════════════════════════╗");
    println!("║         RS256 BENCHMARK RESULTS                ║");
    println!("╠════════════════════════════════════════════════╣");
    println!("║ TIMING                                         ║");
    println!("╠════════════════════════════════════════════════╣");
    println!(
        "║ Witness Gen:              {:>10} ms        ║",
        witness_gen_ms
    );
    println!("║ Setup:                    {:>10} ms        ║", setup_ms);
    println!("║ Prove:                    {:>10} ms        ║", prove_ms);
    println!("║ Verify:                   {:>10} ms        ║", verify_ms);
    println!("╠════════════════════════════════════════════════╣");
    println!("║ SIZES                                          ║");
    println!("╠════════════════════════════════════════════════╣");
    println!(
        "║ Proving Key:               {:>12}        ║",
        format_size(pk_bytes)
    );
    println!(
        "║ Verifying Key:             {:>12}        ║",
        format_size(vk_bytes)
    );
    println!(
        "║ Proof:                     {:>12}        ║",
        format_size(proof_bytes)
    );
    println!(
        "║ Witness:                   {:>12}        ║",
        format_size(witness_bytes)
    );
    println!("╚════════════════════════════════════════════════╝\n");
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
        "cert-chain" => parse_circuit_command(&args[1..]),
        "user-sig" => parse_circuit_command(&args[1..]),
        other => Err(format!("Unknown command '{other}'")),
    }
}

fn parse_circuit_command(tail: &[String]) -> Result<ParsedCommand, String> {
    if tail.is_empty() {
        return Ok(ParsedCommand {
            action: CircuitAction::Run,
            options: CommandOptions::default(),
        });
    }

    let first = &tail[0];
    let (action, option_start) = match first.as_str() {
        "run" => (CircuitAction::Run, 1),
        "setup" => (CircuitAction::Setup, 1),
        "prove" => (CircuitAction::Prove, 1),
        "verify" => (CircuitAction::Verify, 1),
        "benchmark" => (CircuitAction::Benchmark, 1),
        s if s.starts_with('-') => (CircuitAction::Run, 0),
        other => {
            return Err(format!(
                "Unknown action '{other}'. Expected one of run|setup|prove|verify|benchmark."
            ))
        }
    };

    let options_slice = &tail[option_start..];
    let options = parse_options(options_slice)?;

    Ok(ParsedCommand { action, options })
}

fn parse_options(args: &[String]) -> Result<CommandOptions, String> {
    let mut options = CommandOptions::default();
    let mut index = 0;

    while index < args.len() {
        let arg = &args[index];
        if arg == "--input" || arg == "-i" {
            index += 1;
            let value = args
                .get(index)
                .ok_or_else(|| "Missing value for --input".to_string())?;
            options.input = Some(PathBuf::from(value));
        } else if let Some(value) = arg.strip_prefix("--input=") {
            if value.is_empty() {
                return Err("Missing value for --input".into());
            }
            options.input = Some(PathBuf::from(value));
        } else if arg == "--cert-chain-4096" || arg == "-4" {
            options.rs4096 = true;
        } else if arg == "--help" || arg == "-h" {
            print_usage();
            process::exit(0);
        } else {
            return Err(format!("Unknown option '{arg}'"));
        }
        index += 1;
    }

    Ok(options)
}

fn print_usage() {
    eprintln!(
        "Usage:
  ecdsa-spartan2 <command> <action> [options]

Commands:
  cert-chain           Certificate chain verification (Circuit A)
  user-sig             User signature verification (Circuit B)
  generate-split-input Generate split circuit input JSONs
  link-verify          Verify pk_commit equality across cert-chain and user-sig proofs

Actions:
  run                  Run the complete circuit (setup, prove, verify)
  setup                Generate proving and verifying keys
  prove                Generate proof
  verify               Verify proof
  benchmark            Run complete benchmark pipeline

Options:
  --input, -i <path>   Override the circuit input JSON
  --cert-chain-4096, -4  Use RSA-4096 cert-chain circuit (4096-bit issuer CA)

Live mode options (for generate-split-input):
  --pin <pin>                Card PIN (6-8 digits) — triggers live mode
  --hipki-server <url>       HiPKI server URL (default: http://localhost:61161)
  --challenge-server <url>   Challenge server URL (default: http://localhost:8080)
  --smt-server <url>         SMT server URL for revocation proof (optional)
  --issuer <id>              Issuer identifier (default: g2, or g3 with -4)
  --pk-blind <decimal>       Override the per-session pk_blind with a fixed
                             decimal field element (for reproducible fixtures)

Examples:
  cargo run --release -- generate-split-input
  cargo run --release -- generate-split-input --cert-chain-4096
  cargo run --release --features cert_chain_rs2048 -- cert-chain setup
  cargo run --release --features cert_chain_rs2048 -- cert-chain prove --input ../circom/inputs/cert_chain_rs2048/input.json
  cargo run --release --features cert_chain_rs2048 -- cert-chain verify
  cargo run --release --features user_sig_rs2048 -- user-sig setup
  cargo run --release --features user_sig_rs2048 -- user-sig prove --input ../circom/inputs/user_sig_rs2048/input.json
  cargo run --release --features user_sig_rs2048 -- user-sig verify
  cargo run --release -- link-verify
  cargo run --release -- link-verify --cert-chain-4096

Live mode examples:
  cargo run --release -- generate-split-input --pin 830929
  cargo run --release -- generate-split-input --cert-chain-4096 --pin 830929
  cargo run --release -- generate-split-input --pin 830929 --smt-server http://localhost:3000
  cargo run --release -- generate-split-input --pin 830929 --challenge-server http://localhost:8080"
    );
}

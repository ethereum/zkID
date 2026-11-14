mod smt;

use ecdsa_spartan2::{
    generate_split_inputs, load_proof, prove_circuit, prove_circuit_with_pk, save_keys,
    serial_bytes_to_hex_trimmed, setup_circuit_keys, setup_circuit_keys_no_save, verify_circuit,
    verify_circuit_with_loaded_data, CertChainRs4096Circuit, CertChainRsa4096, UserSigCircuit,
    UserSigRsa2048, PathConfig, RsaKeySize, MAX_CERT_CHAIN_LENGTH,
};
use std::path::PathBuf;

// Initializes the shared UniFFI scaffolding and defines the `MoproError` enum.
mopro_ffi::app!();

// ============================================================================
// Core Types
// ============================================================================

/// Result of a proving operation with timing and proof metadata.
/// `prove_ms` is the total time for both circuits; `proof_size_bytes` is the combined size.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ProofResult {
    pub prove_ms: u64,
    pub proof_size_bytes: u64,
}

/// Result of a complete benchmark run with timing and size metrics
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct BenchmarkResults {
    // Timing metrics (milliseconds) — combined across both circuits
    pub setup_ms: u64,
    pub prove_ms: u64,
    pub verify_ms: u64,
    // Size metrics (bytes) — combined across both circuits
    pub proving_key_bytes: u64,
    pub verifying_key_bytes: u64,
    pub proof_bytes: u64,
    pub witness_bytes: u64,
}

impl BenchmarkResults {
    /// Format bytes into human-readable size string
    pub fn format_size(bytes: u64) -> String {
        if bytes < 1024 {
            format!("{} B", bytes)
        } else if bytes < 1024 * 1024 {
            format!("{:.2} KB", bytes as f64 / 1024.0)
        } else {
            format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
        }
    }
}

/// Errors that can occur during ZK proof operations
#[derive(Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum ZkProofError {
    FileNotFound { msg: String },
    ProofGenerationFailed { msg: String },
    VerificationFailed { msg: String },
    InvalidInput { msg: String },
    SetupRequired { msg: String },
    IoError { msg: String },
}

impl std::fmt::Display for ZkProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZkProofError::FileNotFound { msg } => write!(f, "File not found: {}", msg),
            ZkProofError::ProofGenerationFailed { msg } => {
                write!(f, "Proof generation failed: {}", msg)
            }
            ZkProofError::VerificationFailed { msg } => {
                write!(f, "Verification failed: {}", msg)
            }
            ZkProofError::InvalidInput { msg } => write!(f, "Invalid input: {}", msg),
            ZkProofError::SetupRequired { msg } => write!(f, "Setup required: {}", msg),
            ZkProofError::IoError { msg } => write!(f, "IO error: {}", msg),
        }
    }
}

impl std::error::Error for ZkProofError {}

impl From<std::io::Error> for ZkProofError {
    fn from(e: std::io::Error) -> Self {
        ZkProofError::IoError { msg: e.to_string() }
    }
}

impl From<serde_json::Error> for ZkProofError {
    fn from(e: serde_json::Error) -> Self {
        ZkProofError::InvalidInput { msg: e.to_string() }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn make_config(documents_path: &str) -> PathConfig {
    PathConfig::mobile(documents_path)
}

fn get_file_size(path: impl AsRef<std::path::Path>) -> Result<u64, ZkProofError> {
    let path = path.as_ref();
    let metadata = std::fs::metadata(path).map_err(|e| ZkProofError::FileNotFound {
        msg: format!("Failed to get file size from '{}': {}", path.display(), e),
    })?;
    Ok(metadata.len())
}

// ============================================================================
// Input Generation
// ============================================================================

/// Generate split circuit inputs for both cert_chain_rs4096 and user_sig_rs2048.
///
/// Writes two JSON files into `output_dir`:
///   - `cert_chain_rs4096_input.json`
///   - `user_sig_rs2048_input.json`
///
/// These are the input files expected by `prove` via `PathConfig::mobile`.
///
/// `smt_proof` should be the non-membership proof for the certificate's serial
/// number, produced by `create_smt_proof_from_gz` / `create_smt_proof`.
/// Pass `None` to omit SMT revocation checking.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn generate_cert_chain_rs4096_input(
    certb64: String,
    signed_response: String,
    tbs: String,
    issuer_cert_path: String,
    smt_snapshot_path: Option<String>,
    output_dir: String,
    challenge: String,
) -> Result<String, ZkProofError> {
    let user_cert = CertChainRs4096Circuit::generate_user_cert_from_certb64(&certb64)
        .map_err(|e| ZkProofError::InvalidInput { msg: e.to_string() })?;

    let issuer_cert = CertChainRs4096Circuit::fetch_cert_from_file(&issuer_cert_path)
        .map_err(|e| ZkProofError::InvalidInput { msg: e.to_string() })?;

    let serial_hex =
        serial_bytes_to_hex_trimmed(user_cert.tbs_certificate.serial_number.as_bytes());

    // If a snapshot path is provided, build the SMT proof from it.
    let smt_inputs: Option<ecdsa_spartan2::smt_client::SmtCircuitInputs> = smt_snapshot_path
        .map(|path| -> Result<_, ZkProofError> {
            let gz_bytes =
                std::fs::read(&path).map_err(|e| ZkProofError::IoError { msg: e.to_string() })?;
            let proof = create_smt_proof_from_gz(gz_bytes, serial_hex.clone())?;
            let ci = smt_proof_to_circuit_inputs(proof, 128)?;
            Ok(ecdsa_spartan2::smt_client::SmtCircuitInputs {
                smt_root: ci.smt_root,
                serial_number: ci.serial_number,
                smt_siblings: ci.smt_siblings,
                smt_old_key: ci.smt_old_key,
                smt_old_value: ci.smt_old_value,
                smt_is_old0: ci.smt_is_old0,
            })
        })
        .transpose()?;

    let pk_blind = ecdsa_spartan2::random_pk_blind();
    // The cert-chain proof checks the cert's validity period at this time.
    let current_time = ecdsa_spartan2::current_time_utc();
    let (cert_chain_json, user_sig_json) = generate_split_inputs(
        &user_cert,
        &issuer_cert,
        &signed_response,
        tbs.as_bytes(),
        &serial_hex,
        smt_inputs.as_ref(),
        CertChainRsa4096::RSA_K, // k_issuer = 34 (RSA-4096 CA)
        UserSigRsa2048::RSA_K, // k_user   = 17 (RSA-2048 device key)
        MAX_CERT_CHAIN_LENGTH,
        &pk_blind,
        &challenge,
        &current_time,
    )
    .map_err(|e| ZkProofError::InvalidInput { msg: e.to_string() })?;

    let out = PathBuf::from(&output_dir);
    std::fs::create_dir_all(&out)?;

    let cc_path = out.join(format!("{}_input.json", CertChainRsa4096::CIRCUIT_NAME));
    let ds_path = out.join(format!("{}_input.json", UserSigRsa2048::CIRCUIT_NAME));

    std::fs::write(&cc_path, serde_json::to_string_pretty(&cert_chain_json)?)
        .map_err(|e| ZkProofError::IoError { msg: e.to_string() })?;
    std::fs::write(&ds_path, serde_json::to_string_pretty(&user_sig_json)?)
        .map_err(|e| ZkProofError::IoError { msg: e.to_string() })?;

    Ok(format!(
        "Inputs written: cert_chain={}, user_sig={}",
        cc_path.display(),
        ds_path.display()
    ))
}

// ============================================================================
// Setup Operation
// ============================================================================

/// Setup circuit keys for both cert_chain_rs4096 and user_sig_rs2048.
///
/// Requires that `{documents_path}/certChainRS4096.r1cs` and
/// `{documents_path}/userSigRS2048.r1cs` are present.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn setup_keys(documents_path: String) -> Result<String, ZkProofError> {
    let config = make_config(&documents_path);

    let cc_circuit = CertChainRs4096Circuit::new(config.clone(), None);
    let ds_circuit = UserSigCircuit::new(config.clone(), None);

    let start = std::time::Instant::now();
    setup_circuit_keys(
        cc_circuit,
        config.key_path(CertChainRsa4096::PROVING_KEY),
        config.key_path(CertChainRsa4096::VERIFYING_KEY),
    );
    setup_circuit_keys(
        ds_circuit,
        config.key_path(UserSigRsa2048::PROVING_KEY),
        config.key_path(UserSigRsa2048::VERIFYING_KEY),
    );
    let elapsed_ms = start.elapsed().as_millis();

    Ok(format!(
        "cert_chain_rs4096 + user_sig_rs2048 keys setup completed in {}ms",
        elapsed_ms
    ))
}

// ============================================================================
// Prove Operation
// ============================================================================

/// Generate proofs for cert_chain_rs4096 circuit.
///
/// Reads input JSONs via `PathConfig::mobile(documents_path)`:
///   - `{documents_path}/cert_chain_rs4096_input.json`
///
/// Writes proofs, instances, and witnesses under `{documents_path}/keys/`.
///
/// Witnesses are pre-warmed before any Spartan2 key I/O so that witnesscalc's
/// C++ realloc runs on a clean heap and avoids macOS SIGSEGV from moved pointers.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn prove_cert_chain_rs4096(documents_path: String) -> Result<ProofResult, ZkProofError> {
    let config = make_config(&documents_path);

    let input_dir = PathBuf::from(documents_path)
        .join(format!("{}_input.json", CertChainRsa4096::CIRCUIT_NAME));

    if !input_dir.exists() {
        return Err(ZkProofError::FileNotFound {
            msg: format!(
                "cert_chain_rs4096 input file not found: {}",
                input_dir.display()
            ),
        });
    }

    // Pre-warm witness caches on a clean heap before any large allocations.
    let cc_circuit = CertChainRs4096Circuit::new(config.clone(), Some(input_dir));

    // --- cert_chain_rs4096: load PK (mmap), prove with cached witness ---
    let cc_start = std::time::Instant::now();
    prove_circuit(
        cc_circuit,
        config.key_path(CertChainRsa4096::PROVING_KEY),
        config.artifact_path(CertChainRsa4096::INSTANCE),
        config.artifact_path(CertChainRsa4096::WITNESS),
        config.artifact_path(CertChainRsa4096::PROOF),
    );
    let cc_prove_ms = cc_start.elapsed().as_millis() as u64;

    let cc_proof_bytes = get_file_size(config.artifact_path(CertChainRsa4096::PROOF))?;

    Ok(ProofResult {
        prove_ms: cc_prove_ms,
        proof_size_bytes: cc_proof_bytes,
    })
}

/// Generate proofs for both cert_chain_rs4096 and user_sig_rs2048 circuits.
///
/// Reads input JSONs via `PathConfig::mobile(documents_path)`:
///   - `{documents_path}/cert_chain_rs4096_input.json`
///   - `{documents_path}/user_sig_rs2048_input.json`
///
/// Writes proofs, instances, and witnesses under `{documents_path}/keys/`.
///
/// Witnesses are pre-warmed before any Spartan2 key I/O so that witnesscalc's
/// C++ realloc runs on a clean heap and avoids macOS SIGSEGV from moved pointers.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn prove_user_sig_rs2048(documents_path: String) -> Result<ProofResult, ZkProofError> {
    let config = make_config(&documents_path);

    let input_dir = PathBuf::from(documents_path)
        .join(format!("{}_input.json", UserSigRsa2048::CIRCUIT_NAME));

    if !input_dir.exists() {
        return Err(ZkProofError::FileNotFound {
            msg: format!(
                "user_sig_rs2048 input file not found: {}",
                input_dir.display()
            ),
        });
    }

    let ds_circuit = UserSigCircuit::new(config.clone(), Some(input_dir));

    // --- user_sig_rs2048: prove with cached witness ---
    let ds_start = std::time::Instant::now();
    prove_circuit(
        ds_circuit,
        config.key_path(UserSigRsa2048::PROVING_KEY),
        config.artifact_path(UserSigRsa2048::INSTANCE),
        config.artifact_path(UserSigRsa2048::WITNESS),
        config.artifact_path(UserSigRsa2048::PROOF),
    );
    let ds_prove_ms = ds_start.elapsed().as_millis() as u64;

    let ds_proof_bytes = get_file_size(config.artifact_path(UserSigRsa2048::PROOF))?;

    Ok(ProofResult {
        prove_ms: ds_prove_ms,
        proof_size_bytes: ds_proof_bytes,
    })
}

// ============================================================================
// Verify Operation
// ============================================================================

/// Verify proofs for cert_chain_rs4096 circuit.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_cert_chain_rs4096(documents_path: String) -> Result<bool, ZkProofError> {
    let config = make_config(&documents_path);

    verify_circuit(
        config.artifact_path(CertChainRsa4096::PROOF),
        config.key_path(CertChainRsa4096::VERIFYING_KEY),
    );

    Ok(true)
}

/// Verify proofs for user_sig_rs2048 circuit.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_user_sig_rs2048(documents_path: String) -> Result<bool, ZkProofError> {
    let config = make_config(&documents_path);

    verify_circuit(
        config.artifact_path(UserSigRsa2048::PROOF),
        config.key_path(UserSigRsa2048::VERIFYING_KEY),
    );

    Ok(true)
}

/// Verify proofs for cert_chain_rs4096 and user_sig_rs2048 circuits.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn link_verify(documents_path: String) -> Result<bool, ZkProofError> {
    let config = make_config(&documents_path);

    let cc_public_values = verify_circuit(
        config.artifact_path(CertChainRsa4096::PROOF),
        config.key_path(CertChainRsa4096::VERIFYING_KEY),
    );
    let ds_public_values = verify_circuit(
        config.artifact_path(UserSigRsa2048::PROOF),
        config.key_path(UserSigRsa2048::VERIFYING_KEY),
    );

    let pk_commit_a = &cc_public_values[0];
    let pk_commit_b = &ds_public_values[0];

    use ff::PrimeField;
    use subtle::ConstantTimeEq;
    let commits_match: bool = pk_commit_a
        .to_repr()
        .as_ref()
        .ct_eq(pk_commit_b.to_repr().as_ref())
        .into();
    if commits_match {
        Ok(true)
    } else {
        Err(ZkProofError::VerificationFailed {
            msg: "Link verification failed".to_string(),
        })
    }
}

// ============================================================================
// Benchmark Operation
// ============================================================================

/// Run complete benchmark pipeline for both cert_chain_rs4096 and user_sig_rs2048 circuits.
///
/// Witnesses are pre-warmed on a clean heap before Spartan2 setup to prevent macOS SIGSEGV:
/// witnesscalc's C++ `realloc()` moves large allocations on a fragmented heap, leaving stale
/// interior pointers. Pre-warming ensures the realloc happens before heap fragmentation.
/// Each circuit is then processed in isolation (setup → save → drop PK → prove → verify) to
/// avoid holding two large proving keys in memory simultaneously. Timings and sizes are combined.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn run_complete_benchmark(documents_path: String) -> Result<BenchmarkResults, ZkProofError> {
    use ecdsa_spartan2::load_proving_key;
    let config = make_config(&documents_path);

    // ====================================================================
    // Pre-warm witness caches on a clean heap BEFORE any Spartan2 setup.
    // Witnesses are cached in Arc<OnceLock> and shared through clones, so
    // prove_circuit_with_pk reuses them without triggering C++ realloc.
    // ====================================================================
    let cc_circuit = CertChainRs4096Circuit::new(config.clone(), None);
    cc_circuit
        .warm_witness_cache()
        .map_err(|e| ZkProofError::ProofGenerationFailed {
            msg: format!("cert_chain_rs4096 witness pre-warm failed: {}", e),
        })?;

    let ds_circuit = UserSigCircuit::new(config.clone(), None);
    ds_circuit
        .warm_witness_cache()
        .map_err(|e| ZkProofError::ProofGenerationFailed {
            msg: format!("user_sig_rs2048 witness pre-warm failed: {}", e),
        })?;

    // ====================================================================
    // cert_chain_rs4096 — setup, prove, verify
    // ====================================================================

    // Setup: cloning cc_circuit shares the witness cache (Arc), so setup
    // doesn't re-run witnesscalc during the proving shape synthesis.
    let cc_setup_start = std::time::Instant::now();
    let (cc_pk, cc_vk) = setup_circuit_keys_no_save(cc_circuit.clone());
    let cc_setup_ms = cc_setup_start.elapsed().as_millis() as u64;

    save_keys(
        config.key_path(CertChainRsa4096::PROVING_KEY),
        config.key_path(CertChainRsa4096::VERIFYING_KEY),
        &cc_pk,
        &cc_vk,
    )
    .map_err(|e| ZkProofError::IoError {
        msg: format!("Failed to save cert_chain keys: {}", e),
    })?;
    drop(cc_pk); // free large PK before next step

    // Prove: load PK (mmap, no heap fragmentation), prove with cached witness.
    let cc_prove_start = std::time::Instant::now();
    let cc_pk = load_proving_key(config.key_path(CertChainRsa4096::PROVING_KEY)).map_err(|e| {
        ZkProofError::FileNotFound {
            msg: format!("Failed to load cert_chain proving key: {}", e),
        }
    })?;
    prove_circuit_with_pk(
        cc_circuit, // carries pre-warmed witness cache
        &cc_pk,
        config.artifact_path(CertChainRsa4096::INSTANCE),
        config.artifact_path(CertChainRsa4096::WITNESS),
        config.artifact_path(CertChainRsa4096::PROOF),
    );
    let cc_prove_ms = cc_prove_start.elapsed().as_millis() as u64;
    drop(cc_pk);

    // Verify cert_chain proof.
    let cc_proof = load_proof(config.artifact_path(CertChainRsa4096::PROOF)).map_err(|e| {
        ZkProofError::FileNotFound {
            msg: format!("Failed to load cert_chain proof: {}", e),
        }
    })?;
    let cc_verify_start = std::time::Instant::now();
    verify_circuit_with_loaded_data(&cc_proof, &cc_vk);
    let cc_verify_ms = cc_verify_start.elapsed().as_millis() as u64;
    drop(cc_proof);

    // ====================================================================
    // user_sig_rs2048 — setup, prove, verify
    // ====================================================================

    // Setup.
    let ds_setup_start = std::time::Instant::now();
    let (ds_pk, ds_vk) = setup_circuit_keys_no_save(ds_circuit.clone());
    let ds_setup_ms = ds_setup_start.elapsed().as_millis() as u64;

    save_keys(
        config.key_path(UserSigRsa2048::PROVING_KEY),
        config.key_path(UserSigRsa2048::VERIFYING_KEY),
        &ds_pk,
        &ds_vk,
    )
    .map_err(|e| ZkProofError::IoError {
        msg: format!("Failed to save user_sig keys: {}", e),
    })?;
    drop(ds_pk);

    // Prove.
    let ds_prove_start = std::time::Instant::now();
    let ds_pk = load_proving_key(config.key_path(UserSigRsa2048::PROVING_KEY)).map_err(|e| {
        ZkProofError::FileNotFound {
            msg: format!("Failed to load user_sig proving key: {}", e),
        }
    })?;
    prove_circuit_with_pk(
        ds_circuit, // carries pre-warmed witness cache
        &ds_pk,
        config.artifact_path(UserSigRsa2048::INSTANCE),
        config.artifact_path(UserSigRsa2048::WITNESS),
        config.artifact_path(UserSigRsa2048::PROOF),
    );
    let ds_prove_ms = ds_prove_start.elapsed().as_millis() as u64;
    drop(ds_pk);

    // Verify user_sig proof.
    let ds_proof = load_proof(config.artifact_path(UserSigRsa2048::PROOF)).map_err(|e| {
        ZkProofError::FileNotFound {
            msg: format!("Failed to load user_sig proof: {}", e),
        }
    })?;
    let ds_verify_start = std::time::Instant::now();
    verify_circuit_with_loaded_data(&ds_proof, &ds_vk);
    let ds_verify_ms = ds_verify_start.elapsed().as_millis() as u64;
    drop(ds_proof);

    // ====================================================================
    // Collect sizes
    // ====================================================================

    let cc_pk_bytes = get_file_size(config.key_path(CertChainRsa4096::PROVING_KEY))?;
    let cc_vk_bytes = get_file_size(config.key_path(CertChainRsa4096::VERIFYING_KEY))?;
    let cc_proof_bytes = get_file_size(config.artifact_path(CertChainRsa4096::PROOF))?;
    let cc_witness_bytes = get_file_size(config.artifact_path(CertChainRsa4096::WITNESS))?;

    let ds_pk_bytes = get_file_size(config.key_path(UserSigRsa2048::PROVING_KEY))?;
    let ds_vk_bytes = get_file_size(config.key_path(UserSigRsa2048::VERIFYING_KEY))?;
    let ds_proof_bytes = get_file_size(config.artifact_path(UserSigRsa2048::PROOF))?;
    let ds_witness_bytes = get_file_size(config.artifact_path(UserSigRsa2048::WITNESS))?;

    Ok(BenchmarkResults {
        setup_ms: cc_setup_ms + ds_setup_ms,
        prove_ms: cc_prove_ms + ds_prove_ms,
        verify_ms: cc_verify_ms + ds_verify_ms,
        proving_key_bytes: cc_pk_bytes + ds_pk_bytes,
        verifying_key_bytes: cc_vk_bytes + ds_vk_bytes,
        proof_bytes: cc_proof_bytes + ds_proof_bytes,
        witness_bytes: cc_witness_bytes + ds_witness_bytes,
    })
}

// ============================================================================
// SMT (Sparse Merkle Tree) Operations
// ============================================================================

/// SMT proof from the moica-revocation-smt server, all values as hex strings.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SmtProof {
    /// Tree root at proof time (hex string).
    pub root: String,
    /// Sibling hashes from leaf level upward (hex strings).
    pub siblings: Vec<String>,
    /// [key] for non-membership; [key, value, marker] for membership.
    pub entry: Vec<String>,
    /// Present for non-membership proofs when a conflicting leaf exists.
    pub matching_entry: Option<Vec<String>>,
    /// True if the key is claimed to exist in the tree.
    pub membership: bool,
}

/// Circom-ready SMT inputs — all values as decimal strings, siblings padded to depth.
/// Mirrors `ecdsa_spartan2::smt_client::SmtCircuitInputs`.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SmtCircuitInputs {
    pub smt_root: String,
    pub serial_number: String,
    pub smt_siblings: Vec<String>,
    pub smt_old_key: String,
    pub smt_old_value: String,
    pub smt_is_old0: String,
}

/// Verify an SMT non-membership (or membership) proof against a trusted root.
///
/// Recomputes the Merkle root from `proof.entry` + `proof.siblings` using
/// Poseidon-P256, then compares against `expected_root`.  Returns `true` iff
/// the proof is valid.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_smt_proof(proof: SmtProof, expected_root: String) -> bool {
    smt::verify_smt_proof(
        &proof.entry,
        proof.matching_entry.as_ref(),
        &proof.siblings,
        &expected_root,
        proof.membership,
        128,
    )
}

/// Parse a @zk-kit/smt v1.0.2-compatible snapshot JSON and return its root.
///
/// The returned root can be used as `expected_root` in subsequent calls to
/// `verify_smt_proof`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn build_smt_from_snapshot(snapshot_json: String) -> String {
    smt::parse_snapshot_root(&snapshot_json)
}

/// Convert an `SmtProof` (hex strings) into the `SmtCircuitInputs` that the
/// Circom cert-chain circuit expects (decimal strings, siblings padded to `depth`).
///
/// This is the offline equivalent of `ecdsa_spartan2::smt_client::fetch_smt_proof`:
/// instead of hitting the server you supply the proof generated from the local snapshot.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn smt_proof_to_circuit_inputs(
    proof: SmtProof,
    depth: u32,
) -> Result<SmtCircuitInputs, ZkProofError> {
    let depth = depth as usize;

    fn hex_to_dec(s: &str) -> Result<String, ZkProofError> {
        let hex = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        num_bigint::BigUint::parse_bytes(hex.as_bytes(), 16)
            .map(|n| n.to_string())
            .ok_or_else(|| ZkProofError::InvalidInput {
                msg: format!("invalid hex: {}", s),
            })
    }

    let smt_root = hex_to_dec(&proof.root)?;

    let serial_number =
        hex_to_dec(
            proof
                .entry
                .first()
                .ok_or_else(|| ZkProofError::InvalidInput {
                    msg: "empty entry in SmtProof".into(),
                })?,
        )?;

    // Convert siblings and zero-pad to `depth`
    let mut smt_siblings: Vec<String> = proof
        .siblings
        .iter()
        .map(|s| hex_to_dec(s))
        .collect::<Result<_, _>>()?;
    smt_siblings.resize(depth, "0".to_string());
    smt_siblings.truncate(depth);

    // matching_entry present → non-membership with conflict (is_old0 = 0)
    // matching_entry absent  → empty slot              (is_old0 = 1)
    let (smt_old_key, smt_old_value, smt_is_old0) = match &proof.matching_entry {
        Some(me) if me.len() >= 2 => (hex_to_dec(&me[0])?, hex_to_dec(&me[1])?, "0".to_string()),
        _ => ("0".to_string(), "0".to_string(), "1".to_string()),
    };

    Ok(SmtCircuitInputs {
        smt_root,
        serial_number,
        smt_siblings,
        smt_old_key,
        smt_old_value,
        smt_is_old0,
    })
}

/// Load a snapshot and generate a proof for `key_hex` in one call (JSON input).
///
/// # Arguments
/// * `snapshot_json` – decompressed snapshot JSON string
/// * `key_hex`       – certificate serial number as a hex string (with or without `0x`)
///
/// Returns the proof ready to pass straight into `verify_smt_proof`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn create_smt_proof(snapshot_json: String, key_hex: String) -> Result<SmtProof, ZkProofError> {
    let tree = smt::SmtTree::from_json(&snapshot_json)
        .map_err(|e| ZkProofError::InvalidInput { msg: e })?;
    let key = smt::parse_hex(&key_hex);
    let (entry, matching_entry, siblings, membership) = tree.create_proof(&key);
    Ok(SmtProof {
        root: tree.root_hex(),
        siblings,
        entry,
        matching_entry,
        membership,
    })
}

/// Load a snapshot and generate a proof for `key_hex` in one call (gzip input).
///
/// # Arguments
/// * `gz_data` – raw bytes of the `.json.gz` snapshot file
/// * `key_hex` – certificate serial number as a hex string (with or without `0x`)
///
/// Returns the proof ready to pass straight into `verify_smt_proof`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn create_smt_proof_from_gz(
    gz_data: Vec<u8>,
    key_hex: String,
) -> Result<SmtProof, ZkProofError> {
    let tree =
        smt::SmtTree::from_gz(&gz_data).map_err(|e| ZkProofError::InvalidInput { msg: e })?;
    let key = smt::parse_hex(&key_hex);
    let (entry, matching_entry, siblings, membership) = tree.create_proof(&key);
    Ok(SmtProof {
        root: tree.root_hex(),
        siblings,
        entry,
        matching_entry,
        membership,
    })
}

// ============================================================================
// Legacy Test Function
// ============================================================================

/// Test function for basic UniFFI integration
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn mopro_hello_world() -> String {
    "Hello, World!".to_string()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mopro_hello_world() {
        assert_eq!(mopro_hello_world(), "Hello, World!");
    }

    #[test]
    fn test_path_config_mobile_split_circuits() {
        let config = make_config("/app/Documents");

        // cert_chain_rs4096 keys and artifacts
        assert_eq!(
            config.key_path(CertChainRsa4096::PROVING_KEY),
            PathBuf::from("/app/Documents/keys/cert_chain_rs4096_proving.key")
        );
        assert_eq!(
            config.key_path(CertChainRsa4096::VERIFYING_KEY),
            PathBuf::from("/app/Documents/keys/cert_chain_rs4096_verifying.key")
        );
        assert_eq!(
            config.artifact_path(CertChainRsa4096::PROOF),
            PathBuf::from("/app/Documents/keys/cert_chain_rs4096_proof.bin")
        );
        assert_eq!(
            config.artifact_path(CertChainRsa4096::WITNESS),
            PathBuf::from("/app/Documents/keys/cert_chain_rs4096_witness.bin")
        );
        assert_eq!(
            config.artifact_path(CertChainRsa4096::INSTANCE),
            PathBuf::from("/app/Documents/keys/cert_chain_rs4096_instance.bin")
        );

        // user_sig_rs2048 keys and artifacts
        assert_eq!(
            config.key_path(UserSigRsa2048::PROVING_KEY),
            PathBuf::from("/app/Documents/keys/user_sig_rs2048_proving.key")
        );
        assert_eq!(
            config.key_path(UserSigRsa2048::VERIFYING_KEY),
            PathBuf::from("/app/Documents/keys/user_sig_rs2048_verifying.key")
        );
        assert_eq!(
            config.artifact_path(UserSigRsa2048::PROOF),
            PathBuf::from("/app/Documents/keys/user_sig_rs2048_proof.bin")
        );

        // Mobile input JSON paths derived from circuit names
        assert_eq!(
            config.input_json(CertChainRsa4096::CIRCUIT_NAME),
            PathBuf::from("/app/Documents/cert_chain_rs4096_input.json")
        );
        assert_eq!(
            config.input_json(UserSigRsa2048::CIRCUIT_NAME),
            PathBuf::from("/app/Documents/user_sig_rs2048_input.json")
        );
    }

    /// Integration test: prove + verify both circuits.
    ///
    /// Prerequisites:
    ///   - Run `yarn compile:certChainRS4096` and `yarn compile:userSigRS2048`
    ///   - Run `cargo run -- generate-split-input --cert-chain-4096` from ecdsa-spartan2/
    ///
    /// Keys are generated inline during this test (setup is included).
    #[test]
    fn test_prove_verify() -> Result<(), Box<dyn std::error::Error>> {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let documents_path = manifest.join("../ecdsa-spartan2");

        let cc_r1cs_src = manifest
            .join("../circom/build/certChainRS4096/certChainRS4096_js/certChainRS4096.r1cs");
        let ds_r1cs_src = manifest
            .join("../circom/build/userSigRS2048/userSigRS2048_js/userSigRS2048.r1cs");
        assert!(
            cc_r1cs_src.exists(),
            "cert_chain_rs4096 R1CS not found at {}. Run `yarn compile:certChainRS4096` first.",
            cc_r1cs_src.display()
        );
        assert!(
            ds_r1cs_src.exists(),
            "user_sig_rs2048 R1CS not found at {}. Run `yarn compile:userSigRS2048` first.",
            ds_r1cs_src.display()
        );

        let cc_r1cs_dst = documents_path.join("certChainRS4096.r1cs");
        let ds_r1cs_dst = documents_path.join("userSigRS2048.r1cs");
        if !cc_r1cs_dst.exists() {
            std::fs::copy(&cc_r1cs_src, &cc_r1cs_dst)?;
        }
        if !ds_r1cs_dst.exists() {
            std::fs::copy(&ds_r1cs_src, &ds_r1cs_dst)?;
        }

        let cc_input_src = manifest.join("../circom/inputs/cert_chain_rs4096/input.json");
        let ds_input_src =
            manifest.join("../circom/inputs/user_sig_rs2048_chain_rs4096/input.json");
        assert!(
            cc_input_src.exists(),
            "cert_chain_rs4096 input not found at {}.",
            cc_input_src.display()
        );
        assert!(
            ds_input_src.exists(),
            "user_sig input not found at {}.",
            ds_input_src.display()
        );

        std::fs::copy(
            &cc_input_src,
            documents_path.join("cert_chain_rs4096_input.json"),
        )?;
        std::fs::copy(
            &ds_input_src,
            documents_path.join("user_sig_rs2048_input.json"),
        )?;
        std::fs::create_dir_all(documents_path.join("keys"))?;

        let doc_str = documents_path.to_string_lossy().to_string();
        setup_keys(doc_str.clone())?;
        prove_cert_chain_rs4096(doc_str.clone())?;
        let verify_result = verify_cert_chain_rs4096(doc_str.clone())?;
        assert!(verify_result, "cert_chain_rs4096 verification failed");

        prove_user_sig_rs2048(doc_str.clone())?;
        let verify_result = verify_user_sig_rs2048(doc_str.clone())?;
        assert!(verify_result, "user_sig_rs2048 verification failed");

        let link_verify_result = link_verify(doc_str.clone())?;
        assert!(link_verify_result, "link verification failed");

        std::fs::remove_file(cc_r1cs_dst)?;
        std::fs::remove_file(ds_r1cs_dst)?;

        Ok(())
    }

    #[test]
    fn test_complete_benchmark_e2e() {
        use std::os::unix::fs::symlink;

        let tempdir = tempfile::tempdir().expect("Failed to create tempdir");
        let dir = tempdir.path().to_path_buf();

        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let cc_r1cs_src = manifest
            .join("../circom/build/certChainRS4096/certChainRS4096_js/certChainRS4096.r1cs");
        let ds_r1cs_src = manifest
            .join("../circom/build/userSigRS2048/userSigRS2048_js/userSigRS2048.r1cs");
        let cc_input_src = manifest.join("../circom/inputs/cert_chain_rs4096/input.json");
        let ds_input_src =
            manifest.join("../circom/inputs/user_sig_rs2048_chain_rs4096/input.json");

        assert!(
            cc_r1cs_src.exists(),
            "cert_chain_rs4096 R1CS not found at {}. Run `yarn compile:certChainRS4096` first.",
            cc_r1cs_src.display()
        );
        assert!(
            ds_r1cs_src.exists(),
            "user_sig_rs2048 R1CS not found at {}. Run `yarn compile:userSigRS2048` first.",
            ds_r1cs_src.display()
        );
        assert!(
            cc_input_src.exists(),
            "cert_chain_rs4096 input not found at {}. Run `cargo run -- generate-split-input --cert-chain-4096` first.",
            cc_input_src.display()
        );
        assert!(
            ds_input_src.exists(),
            "user_sig input not found at {}. Run `cargo run -- generate-split-input --cert-chain-4096` first.",
            ds_input_src.display()
        );

        symlink(&cc_r1cs_src, dir.join("certChainRS4096.r1cs"))
            .expect("Failed to symlink cert_chain R1CS");
        symlink(&ds_r1cs_src, dir.join("userSigRS2048.r1cs"))
            .expect("Failed to symlink user_sig R1CS");
        symlink(&cc_input_src, dir.join("cert_chain_rs4096_input.json"))
            .expect("Failed to symlink cert_chain input");
        symlink(&ds_input_src, dir.join("user_sig_rs2048_input.json"))
            .expect("Failed to symlink user_sig input");
        std::fs::create_dir(dir.join("keys")).expect("Failed to create keys dir");

        // 256 MB outer stack: cert_chain_rs4096 Spartan2 proving uses deep call frames.
        // Each circuit's witness generation additionally spawns its own 256 MB thread.
        let dir_str = dir.to_string_lossy().to_string();
        let results = std::thread::Builder::new()
            .stack_size(256 * 1024 * 1024)
            .spawn(move || run_complete_benchmark(dir_str).expect("run_complete_benchmark failed"))
            .expect("Failed to spawn thread")
            .join()
            .expect("Thread panicked");

        assert!(results.setup_ms > 0, "setup_ms should be > 0");
        assert!(results.prove_ms > 0, "prove_ms should be > 0");
        assert!(results.verify_ms > 0, "verify_ms should be > 0");
        assert!(
            results.proving_key_bytes > 0,
            "proving_key_bytes should be > 0"
        );
        assert!(
            results.verifying_key_bytes > 0,
            "verifying_key_bytes should be > 0"
        );
        assert!(results.proof_bytes > 0, "proof_bytes should be > 0");
        assert!(results.witness_bytes > 0, "witness_bytes should be > 0");

        let keys_dir = dir.join("keys");
        assert!(keys_dir.join(CertChainRsa4096::PROVING_KEY).exists());
        assert!(keys_dir.join(CertChainRsa4096::VERIFYING_KEY).exists());
        assert!(keys_dir.join(CertChainRsa4096::PROOF).exists());
        assert!(keys_dir.join(CertChainRsa4096::WITNESS).exists());
        assert!(keys_dir.join(CertChainRsa4096::INSTANCE).exists());
        assert!(keys_dir.join(UserSigRsa2048::PROVING_KEY).exists());
        assert!(keys_dir.join(UserSigRsa2048::VERIFYING_KEY).exists());
        assert!(keys_dir.join(UserSigRsa2048::PROOF).exists());
        assert!(keys_dir.join(UserSigRsa2048::WITNESS).exists());
        assert!(keys_dir.join(UserSigRsa2048::INSTANCE).exists());

        eprintln!("\n=== cert_chain_rs4096 + user_sig_rs2048 Benchmark Results ===");
        eprintln!("Setup:  {}ms", results.setup_ms);
        eprintln!("Prove:  {}ms", results.prove_ms);
        eprintln!("Verify: {}ms", results.verify_ms);
        eprintln!(
            "PK: {}, VK: {}, Proof: {}, Witness: {}",
            BenchmarkResults::format_size(results.proving_key_bytes),
            BenchmarkResults::format_size(results.verifying_key_bytes),
            BenchmarkResults::format_size(results.proof_bytes),
            BenchmarkResults::format_size(results.witness_bytes),
        );
    }

    #[ignore]
    #[test]
    fn test_generate_cert_chain_rs4096_input_e2e() {
        use ecdsa_spartan2::{circuits::types::Rs4096SignResponse, DEFAULT_CHALLENGE};

        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

        let response_path =
            manifest.join("../ecdsa-spartan2/tests/testdata/rs4096_response_sign.json");
        let response_str = std::fs::read_to_string(&response_path).unwrap();
        let response: Rs4096SignResponse = serde_json::from_str(&response_str).unwrap();
        let certb64 = response.result.cert;
        let signed_response = response.result.signed_response;
        let tbs = std::str::from_utf8(ecdsa_spartan2::DEFAULT_TBS)
            .unwrap()
            .to_string();
        let issuer_cert_path = manifest.join("../ecdsa-spartan2/tests/testdata/test_ca_rs4096.der");

        // Use a temp dir as documents_path so input + key files stay isolated.
        let tmp = tempfile::tempdir().unwrap();
        let documents_path = tmp.path().to_string_lossy().to_string();
        std::fs::create_dir_all(tmp.path().join("keys")).unwrap();

        // Copy R1CS files — built by `yarn compile:certChainRS4096/user_sig_rs2048`.
        let cc_r1cs_src = manifest
            .join("../circom/build/certChainRS4096/certChainRS4096_js/certChainRS4096.r1cs");
        let ds_r1cs_src = manifest
            .join("../circom/build/userSigRS2048/userSigRS2048_js/userSigRS2048.r1cs");
        assert!(
            cc_r1cs_src.exists(),
            "cert_chain_rs4096 R1CS not found at {}. Run `yarn compile:certChainRS4096` first.",
            cc_r1cs_src.display()
        );
        assert!(
            ds_r1cs_src.exists(),
            "user_sig_rs2048 R1CS not found at {}. Run `yarn compile:userSigRS2048` first.",
            ds_r1cs_src.display()
        );
        std::fs::copy(&cc_r1cs_src, tmp.path().join("certChainRS4096.r1cs")).unwrap();
        std::fs::copy(&ds_r1cs_src, tmp.path().join("userSigRS2048.r1cs")).unwrap();

        // Generate circuit inputs, writing directly into documents_path.
        let snapshot_path = "/tmp/g3-tree-snapshot.json.gz";
        let smt_snapshot = std::path::Path::new(snapshot_path)
            .exists()
            .then(|| snapshot_path.to_string());

        let challenge = DEFAULT_CHALLENGE.to_string();
        let result = generate_cert_chain_rs4096_input(
            certb64,
            signed_response,
            tbs,
            issuer_cert_path.to_string_lossy().to_string(),
            smt_snapshot,
            documents_path.clone(),
            challenge,
        )
        .unwrap();
        assert!(result.contains("cert_chain"));
        assert!(result.contains("user_sig"));

        // Setup, prove, verify both circuits.
        setup_keys(documents_path.clone()).unwrap();

        let cc_result = prove_cert_chain_rs4096(documents_path.clone()).unwrap();
        println!("cert_chain proved in {}ms", cc_result.prove_ms);
        let cc_ok = verify_cert_chain_rs4096(documents_path.clone()).unwrap();
        assert!(cc_ok, "cert_chain_rs4096 verification failed");

        let ds_result = prove_user_sig_rs2048(documents_path.clone()).unwrap();
        println!("user_sig proved in {}ms", ds_result.prove_ms);
        let ds_ok = verify_user_sig_rs2048(documents_path.clone()).unwrap();
        assert!(ds_ok, "user_sig_rs2048 verification failed");

        let linked = link_verify(documents_path.clone()).unwrap();
        assert!(linked, "link verification failed");
        println!("All proofs verified successfully");
    }
}

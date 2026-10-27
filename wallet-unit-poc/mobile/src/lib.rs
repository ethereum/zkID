use ecdsa_spartan2::{
    generate_prepare_witness, load_instance, load_proof, load_proving_key, load_shared_blinds,
    load_witness, prove_circuit_in_memory, reblind_in_memory,
    paths::keys::{
        PREPARE_INSTANCE, PREPARE_PROOF, PREPARE_PROVING_KEY, PREPARE_VERIFYING_KEY,
        PREPARE_WITNESS, SHARED_BLINDS, SHOW_INSTANCE, SHOW_PROOF, SHOW_PROVING_KEY,
        SHOW_VERIFYING_KEY, SHOW_WITNESS,
    },
    prover::{
        generate_shared_blinds as gen_shared_blinds, prove_circuit, prove_circuit_with_pk, reblind,
        reblind_with_loaded_data, try_verify_circuit, verify_circuit_with_loaded_data,
        verify_linked_paths,
    },
    save_keys,
    setup::{setup_circuit_keys, setup_circuit_keys_no_save},
    CircuitSize, PathConfig, PrepareCircuit, ShowCircuit, E,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use spartan2::{
    r1cs::{R1CSWitness, SplitR1CSInstance},
    traits::{snark::R1CSSNARKTrait, Engine},
    zk_spartan::R1CSSNARK,
};

// Initializes the shared UniFFI scaffolding and defines the `MoproError` enum.
mopro_ffi::app!();

const JWT_CIRCUIT_NAME: &str = "jwt";
const SHOW_CIRCUIT_NAME: &str = "show";

// ============================================================================
// Core Types
// ============================================================================

/// Result of a proving operation with timing and proof metadata
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ProofResult {
    pub prep_ms: u64,
    pub prove_ms: u64,
    pub total_ms: u64,
    pub proof_size_bytes: u64,
    pub comm_w_shared: String,
}

/// Result of a complete benchmark run with timing and size metrics
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct BenchmarkResults {
    // Timing metrics (milliseconds)
    pub jwt_setup_ms: u64,
    pub show_setup_ms: u64,
    pub generate_blinds_ms: u64,
    pub prove_jwt_ms: u64,
    pub reblind_jwt_ms: u64,
    pub prove_show_ms: u64,
    pub reblind_show_ms: u64,
    pub verify_jwt_ms: u64,
    pub verify_show_ms: u64,
    // Peak resident set size per step (KiB)
    pub peak_rss_jwt_setup_kb: u64,
    pub peak_rss_show_setup_kb: u64,
    pub peak_rss_generate_blinds_kb: u64,
    pub peak_rss_prove_jwt_kb: u64,
    pub peak_rss_reblind_jwt_kb: u64,
    pub peak_rss_prove_show_kb: u64,
    pub peak_rss_reblind_show_kb: u64,
    pub peak_rss_verify_jwt_kb: u64,
    pub peak_rss_verify_show_kb: u64,
    /// False when the high-water mark could not be reset between steps, so the
    /// peaks are process-wide and non-decreasing.
    pub rss_per_step: bool,
    /// Threads in the rayon pool the benchmark ran on.
    pub pool_threads: u32,
    /// Pool threads whose effective affinity mask equalled the requested
    /// big-core set right after pinning at thread start; 0 when not pinning.
    pub pinned_threads: u32,
    /// The same check repeated after the run. Affinity can be reset mid-run by
    /// cpuset moves on pre-6.2 kernels, so this can be lower than `pinned_threads`.
    pub pinned_threads_end: u32,
    // Size metrics (bytes)
    pub jwt_proving_key_bytes: u64,
    pub jwt_verifying_key_bytes: u64,
    pub show_proving_key_bytes: u64,
    pub show_verifying_key_bytes: u64,
    pub jwt_proof_bytes: u64,
    pub show_proof_bytes: u64,
    pub jwt_witness_bytes: u64,
    pub show_witness_bytes: u64,
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
    FileNotFound { message: String },
    ProofGenerationFailed { message: String },
    VerificationFailed { message: String },
    InvalidInput { message: String },
    SetupRequired { message: String },
    IoError { message: String },
}

impl std::fmt::Display for ZkProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZkProofError::FileNotFound { message } => write!(f, "File not found: {}", message),
            ZkProofError::ProofGenerationFailed { message } => {
                write!(f, "Proof generation failed: {}", message)
            }
            ZkProofError::VerificationFailed { message } => {
                write!(f, "Verification failed: {}", message)
            }
            ZkProofError::InvalidInput { message } => write!(f, "Invalid input: {}", message),
            ZkProofError::SetupRequired { message } => write!(f, "Setup required: {}", message),
            ZkProofError::IoError { message } => write!(f, "IO error: {}", message),
        }
    }
}

impl std::error::Error for ZkProofError {}

/// Text of an error that crossed the Flutter bridge, where it arrives as an
/// opaque handle whose `toString` says nothing.
pub fn zk_error_message(e: &ZkProofError) -> String {
    e.to_string()
}

impl From<std::io::Error> for ZkProofError {
    fn from(e: std::io::Error) -> Self {
        ZkProofError::IoError {
            message: e.to_string(),
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a PathConfig for the given documents path (mobile environment).
fn make_config(documents_path: &str) -> PathConfig {
    PathConfig {
        base_dir: documents_path.into(),
        is_mobile: true,
        circuit_size: CircuitSize::Kb2,
    }
}

// ============================================================================
// Setup Operations
// ============================================================================

/// Setup JWT circuit keys
/// Generates proving and verifying keys for the JWT circuit
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn setup_jwt_keys(documents_path: String) -> Result<String, ZkProofError> {
    let config = make_config(&documents_path);
    let circuit = PrepareCircuit::new(config.clone(), None);

    let start = std::time::Instant::now();
    setup_circuit_keys(
        circuit,
        config.key_path(PREPARE_PROVING_KEY),
        config.key_path(PREPARE_VERIFYING_KEY),
    );
    let elapsed_ms = start.elapsed().as_millis();

    Ok(format!(
        "JWT circuit keys setup completed in {}ms",
        elapsed_ms
    ))
}

/// Setup Show circuit keys
/// Generates proving and verifying keys for the Show circuit
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn setup_show_keys(documents_path: String) -> Result<String, ZkProofError> {
    let config = make_config(&documents_path);
    let circuit = ShowCircuit::new(config.clone(), None);

    let start = std::time::Instant::now();
    setup_circuit_keys(
        circuit,
        config.key_path(SHOW_PROVING_KEY),
        config.key_path(SHOW_VERIFYING_KEY),
    );
    let elapsed_ms = start.elapsed().as_millis();

    Ok(format!(
        "Show circuit keys setup completed in {}ms",
        elapsed_ms
    ))
}

// ============================================================================
// Shared Blinds Generation
// ============================================================================

/// Generate shared blinding factors for both circuits
/// Creates random blinding factors that enable proof reblinding
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn generate_shared_blinds(documents_path: String) -> Result<String, ZkProofError> {
    let config = make_config(&documents_path);

    // Note: While circuits have 98 shared values (2 keybindings + 96 claim scalars),
    // Hyrax batches all these into a single commitment point.
    // num_shared_rows() returns the number of Hyrax commitment points, not individual scalars.
    const NUM_SHARED: usize = 1;
    gen_shared_blinds::<E>(config.artifact_path(SHARED_BLINDS), NUM_SHARED);

    Ok("Shared blinds generated successfully".to_string())
}

// ============================================================================
// Prove Operations
// ============================================================================

/// Generate JWT circuit proof
/// Runs prep_prove + prove phases using existing keys
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn prove_jwt(documents_path: String) -> Result<ProofResult, ZkProofError> {
    let config = make_config(&documents_path);
    let input_dir =
        PathBuf::from(documents_path).join(format!("{}_input.json", JWT_CIRCUIT_NAME));

    if !input_dir.exists() {
        return Err(ZkProofError::FileNotFound {
            message: format!("{} input file not found", JWT_CIRCUIT_NAME),
        });
    }
    println!("input_dir: {}", input_dir.display());
    println!(
        "config: {}",
        config.artifact_path(PREPARE_INSTANCE).display()
    );
    println!(
        "key_path: {}",
        config.key_path(PREPARE_PROVING_KEY).display()
    );
    println!(
        "witness_path: {}",
        config.artifact_path(PREPARE_WITNESS).display()
    );
    println!(
        "proof_path: {}",
        config.artifact_path(PREPARE_PROOF).display()
    );

    let circuit = PrepareCircuit::new(config.clone(), Some(input_dir));

    let start = std::time::Instant::now();
    prove_circuit(
        circuit,
        config.key_path(PREPARE_PROVING_KEY),
        config.artifact_path(PREPARE_INSTANCE),
        config.artifact_path(PREPARE_WITNESS),
        config.artifact_path(PREPARE_PROOF),
    );
    let total_ms = start.elapsed().as_millis() as u64;

    // Get proof size and comm_W_shared
    let proof_size_bytes = get_proof_size(&config.artifact_path(PREPARE_PROOF))?;
    let comm_w_shared = extract_comm_w_shared(&config.artifact_path(PREPARE_INSTANCE))?;

    Ok(ProofResult {
        prep_ms: 0, // prover doesn't separate timing
        prove_ms: total_ms,
        total_ms,
        proof_size_bytes,
        comm_w_shared,
    })
}

/// Generate Show circuit proof
/// Runs prep_prove + prove phases using existing keys
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn prove_show(documents_path: String) -> Result<ProofResult, ZkProofError> {
    let config = make_config(&documents_path);
    let input_dir = PathBuf::from(documents_path).join(format!("{}_input.json", SHOW_CIRCUIT_NAME));

    if !input_dir.exists() {
        return Err(ZkProofError::FileNotFound {
            message: format!("{} input file not found", SHOW_CIRCUIT_NAME),
        });
    }

    println!("input_dir: {}", input_dir.display());
    println!(
        "config: {}",
        config.artifact_path(SHOW_INSTANCE).display()
    );
    println!(
        "key_path: {}",
        config.key_path(SHOW_PROVING_KEY).display()
    );
    println!(
        "witness_path: {}",
        config.artifact_path(SHOW_WITNESS).display()
    );
    println!(
        "proof_path: {}",
        config.artifact_path(SHOW_PROOF).display()
    );

    let circuit = ShowCircuit::new(config.clone(), Some(input_dir));

    let start = std::time::Instant::now();
    prove_circuit(
        circuit,
        config.key_path(SHOW_PROVING_KEY),
        config.artifact_path(SHOW_INSTANCE),
        config.artifact_path(SHOW_WITNESS),
        config.artifact_path(SHOW_PROOF),
    );
    let total_ms = start.elapsed().as_millis() as u64;

    // Get proof size and comm_W_shared
    let proof_size_bytes = get_proof_size(&config.artifact_path(SHOW_PROOF))?;
    let comm_w_shared = extract_comm_w_shared(&config.artifact_path(SHOW_INSTANCE))?;

    Ok(ProofResult {
        prep_ms: 0,
        prove_ms: total_ms,
        total_ms,
        proof_size_bytes,
        comm_w_shared,
    })
}

// ============================================================================
// Reblind Operations
// ============================================================================

/// Reblind JWT circuit proof
/// Generates a new unlinkable proof while preserving comm_W_shared
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn reblind_jwt(documents_path: String) -> Result<ProofResult, ZkProofError> {
    let config = make_config(&documents_path);

    let start = std::time::Instant::now();
    reblind(
        config.key_path(PREPARE_PROVING_KEY),
        config.artifact_path(PREPARE_INSTANCE),
        config.artifact_path(PREPARE_WITNESS),
        config.artifact_path(PREPARE_PROOF),
        config.artifact_path(SHARED_BLINDS),
    );
    let elapsed_ms = start.elapsed().as_millis() as u64;

    // Get proof size and comm_W_shared
    let proof_size_bytes = get_proof_size(&config.artifact_path(PREPARE_PROOF))?;
    let comm_w_shared = extract_comm_w_shared(&config.artifact_path(PREPARE_INSTANCE))?;

    Ok(ProofResult {
        prep_ms: 0,
        prove_ms: elapsed_ms,
        total_ms: elapsed_ms,
        proof_size_bytes,
        comm_w_shared,
    })
}

/// Reblind Show circuit proof
/// Generates a new unlinkable proof while preserving comm_W_shared
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn reblind_show(documents_path: String) -> Result<ProofResult, ZkProofError> {
    let config = make_config(&documents_path);

    let start = std::time::Instant::now();
    reblind(
        config.key_path(SHOW_PROVING_KEY),
        config.artifact_path(SHOW_INSTANCE),
        config.artifact_path(SHOW_WITNESS),
        config.artifact_path(SHOW_PROOF),
        config.artifact_path(SHARED_BLINDS),
    );
    let elapsed_ms = start.elapsed().as_millis() as u64;

    // Get proof size and comm_W_shared
    let proof_size_bytes = get_proof_size(&config.artifact_path(SHOW_PROOF))?;
    let comm_w_shared = extract_comm_w_shared(&config.artifact_path(SHOW_INSTANCE))?;

    Ok(ProofResult {
        prep_ms: 0,
        prove_ms: elapsed_ms,
        total_ms: elapsed_ms,
        proof_size_bytes,
        comm_w_shared,
    })
}

// ============================================================================
// Verify Operations
// ============================================================================

/// Verify JWT circuit proof
/// Verifies the proof using the verifying key
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_jwt(documents_path: String) -> Result<bool, ZkProofError> {
    let config = make_config(&documents_path);
    // Item 12: return the REAL result. verify_circuit panicked on an invalid
    // proof and this always returned Ok(true); try_verify_circuit returns a bool.
    Ok(try_verify_circuit(
        config.artifact_path(PREPARE_PROOF),
        config.key_path(PREPARE_VERIFYING_KEY),
    ))
}

/// Verify Show circuit proof
/// Verifies the proof using the verifying key
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_show(documents_path: String) -> Result<bool, ZkProofError> {
    let config = make_config(&documents_path);
    Ok(try_verify_circuit(
        config.artifact_path(SHOW_PROOF),
        config.key_path(SHOW_VERIFYING_KEY),
    ))
}

/// Verify a full presentation: both proofs verify AND commit to the same shared
/// witness (Item 12). This is the check a verifier must make — verifying the two
/// proofs separately does not bind them to the same credential.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_presentation(documents_path: String) -> Result<bool, ZkProofError> {
    let config = make_config(&documents_path);
    Ok(verify_linked_paths(
        config.artifact_path(PREPARE_PROOF),
        config.key_path(PREPARE_VERIFYING_KEY),
        config.artifact_path(SHOW_PROOF),
        config.key_path(SHOW_VERIFYING_KEY),
    ))
}

// ============================================================================
// Loaded-key Operations
// ============================================================================
//
// Production apps ship proving keys instead of running setup on the device. These
// functions load a key once into a process-wide slot and prove with it, all in
// memory: nothing under the documents path is written or overwritten.

type ProvingKey = <R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey;

/// What a presentation reblinds on the Prepare side: the Prepare proof's
/// instance and witness plus the blinds shared with Show.
struct PrepareReblindData {
    instance: SplitR1CSInstance<E>,
    witness: R1CSWitness<E>,
    blinds: Vec<<E as Engine>::Scalar>,
}

struct Loaded {
    prepare_pk: Option<Arc<ProvingKey>>,
    show_pk: Option<Arc<ProvingKey>>,
    prepare_reblind: Option<Arc<PrepareReblindData>>,
}

static LOADED: Mutex<Loaded> = Mutex::new(Loaded {
    prepare_pk: None,
    show_pk: None,
    prepare_reblind: None,
});

/// Tests share the process-wide slots; hold this while touching them.
#[cfg(test)]
static LOADED_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
fn clear_loaded_for_test() {
    let mut loaded = LOADED.lock().unwrap();
    loaded.prepare_pk = None;
    loaded.show_pk = None;
    loaded.prepare_reblind = None;
}

/// Timing of one loaded-key proof. `witness_ms` is the Prepare witness
/// generation, which is part of `prove_ms`; Show's witness is generated inside
/// the prover and cannot be timed apart, so it reports 0.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct LoadedProofResult {
    pub witness_ms: u64,
    pub prove_ms: u64,
    pub proof_bytes: u64,
}

/// Timing and peak RSS of one presentation: Show prove, then reblind of the
/// Prepare and Show proofs. Each peak is read after a reset at the start of its
/// sub-step; `peak_rss_kb` is the maximum over the whole presentation.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PresentResult {
    pub show_prove_ms: u64,
    pub prepare_reblind_ms: u64,
    pub show_reblind_ms: u64,
    pub total_ms: u64,
    pub peak_rss_show_prove_kb: u64,
    pub peak_rss_prepare_reblind_kb: u64,
    pub peak_rss_show_reblind_kb: u64,
    pub peak_rss_kb: u64,
    pub rss_per_step: bool,
    pub prepare_proof_bytes: u64,
    pub show_proof_bytes: u64,
}

fn max_peak(peaks: &[u64]) -> u64 {
    peaks.iter().copied().max().unwrap_or(0)
}

fn load_key(path: &str) -> Result<(ProvingKey, u64), ZkProofError> {
    let start = std::time::Instant::now();
    let pk = load_proving_key(path).map_err(|e| ZkProofError::FileNotFound {
        message: format!("Failed to load proving key '{}': {}", path, e),
    })?;
    Ok((pk, start.elapsed().as_millis() as u64))
}

/// Copies `src` to `dest` (creating parent directories), flushes it, and drops
/// both files from the page cache so the next load reads from storage rather
/// than RAM. Returns the bytes copied. Pushed files live on emulated external
/// storage; apps ship keys on internal storage, so benchmarks stage them there.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn stage_file(src: String, dest: String) -> Result<u64, ZkProofError> {
    let dest_path = Path::new(&dest);
    if let Some(parent) = dest_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut input = std::fs::File::open(&src).map_err(|e| ZkProofError::FileNotFound {
        message: format!("Failed to open '{}': {}", src, e),
    })?;
    let mut output = std::fs::File::create(dest_path).map_err(|e| ZkProofError::IoError {
        message: format!("Failed to create '{}': {}", dest, e),
    })?;
    let bytes = std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    drop_page_cache(Path::new(&src));
    drop_page_cache(dest_path);
    Ok(bytes)
}

/// Best effort: advice the kernel may ignore, and an unreadable file only means
/// the next load is warmer than intended.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn drop_page_cache(path: &Path) {
    use std::os::fd::AsRawFd;
    if let Ok(f) = std::fs::File::open(path) {
        // SAFETY: the fd is valid for the call; offset 0 and length 0 mean the whole file.
        unsafe { libc::posix_fadvise(f.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn drop_page_cache(_path: &Path) {}

/// Load the Prepare (JWT) proving key from `path`; returns load time in ms.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn load_prepare_key(path: String) -> Result<u64, ZkProofError> {
    let (pk, ms) = load_key(&path)?;
    LOADED.lock().unwrap().prepare_pk = Some(Arc::new(pk));
    Ok(ms)
}

/// Load the Show proving key from `path`; returns load time in ms.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn load_show_key(path: String) -> Result<u64, ZkProofError> {
    let (pk, ms) = load_key(&path)?;
    LOADED.lock().unwrap().show_pk = Some(Arc::new(pk));
    Ok(ms)
}

/// Load the Prepare instance and witness and the shared blinds a presentation
/// reblinds; returns load time in ms.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn load_prepare_reblind_data(
    instance_path: String,
    witness_path: String,
    shared_blinds_path: String,
) -> Result<u64, ZkProofError> {
    let missing = |what: &str, e: Box<dyn std::error::Error>| ZkProofError::FileNotFound {
        message: format!("Failed to load {}: {}", what, e),
    };
    let start = std::time::Instant::now();
    let instance = load_instance(&instance_path).map_err(|e| missing("prepare instance", e))?;
    let witness = load_witness(&witness_path).map_err(|e| missing("prepare witness", e))?;
    let blinds =
        load_shared_blinds::<E>(&shared_blinds_path).map_err(|e| missing("shared blinds", e))?;
    let ms = start.elapsed().as_millis() as u64;
    LOADED.lock().unwrap().prepare_reblind = Some(Arc::new(PrepareReblindData {
        instance,
        witness,
        blinds,
    }));
    Ok(ms)
}

fn proof_bytes(proof: &R1CSSNARK<E>) -> Result<u64, ZkProofError> {
    bincode::serialized_size(proof).map_err(|e| ZkProofError::IoError {
        message: format!("Failed to size proof: {}", e),
    })
}

fn require<T: Clone>(slot: Option<&T>, what: &str) -> Result<T, ZkProofError> {
    slot.cloned().ok_or_else(|| ZkProofError::SetupRequired {
        message: format!("{} not loaded", what),
    })
}

fn input_path(documents_path: &str, circuit: &str) -> PathBuf {
    PathBuf::from(documents_path).join(format!("{}_input.json", circuit))
}

fn proving_failed(e: impl std::fmt::Display) -> ZkProofError {
    ZkProofError::ProofGenerationFailed {
        message: e.to_string(),
    }
}

type InMemoryProof = (R1CSSNARK<E>, SplitR1CSInstance<E>, R1CSWitness<E>);

/// Returns the proof plus the Prepare witness-generation time in ms.
fn prove_prepare_in_memory(
    documents_path: &str,
    pk: &ProvingKey,
) -> Result<(InMemoryProof, u64), ZkProofError> {
    let config = make_config(documents_path);
    let input = input_path(documents_path, JWT_CIRCUIT_NAME);
    let t = std::time::Instant::now();
    let witness = generate_prepare_witness(&config, Some(&input)).map_err(proving_failed)?;
    let witness_ms = t.elapsed().as_millis() as u64;
    let circuit = PrepareCircuit::with_witness_for_size(witness, config.circuit_size);
    let proved = prove_circuit_in_memory(circuit, pk).map_err(proving_failed)?;
    Ok((proved, witness_ms))
}

fn prove_show_in_memory(
    documents_path: &str,
    pk: &ProvingKey,
) -> Result<InMemoryProof, ZkProofError> {
    let config = make_config(documents_path);
    let circuit = ShowCircuit::new(config, Some(input_path(documents_path, SHOW_CIRCUIT_NAME)));
    prove_circuit_in_memory(circuit, pk).map_err(proving_failed)
}

/// Prove Prepare with the loaded key. Witness generation is included in
/// `prove_ms`. Reads `jwt_input.json` under `documents_path`; no r1cs is read.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn prove_prepare_loaded(documents_path: String) -> Result<LoadedProofResult, ZkProofError> {
    let pk = require(LOADED.lock().unwrap().prepare_pk.as_ref(), "prepare key")?;
    let start = std::time::Instant::now();
    let ((proof, _, _), witness_ms) = prove_prepare_in_memory(&documents_path, &pk)?;
    let prove_ms = start.elapsed().as_millis() as u64;
    Ok(LoadedProofResult {
        witness_ms,
        prove_ms,
        proof_bytes: proof_bytes(&proof)?,
    })
}

/// Prove Show with the loaded key. Witness generation is included in
/// `prove_ms`. Reads `show_input.json` under `documents_path`; no r1cs is read.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn prove_show_loaded(documents_path: String) -> Result<LoadedProofResult, ZkProofError> {
    let pk = require(LOADED.lock().unwrap().show_pk.as_ref(), "show key")?;
    let start = std::time::Instant::now();
    let (proof, _, _) = prove_show_in_memory(&documents_path, &pk)?;
    let prove_ms = start.elapsed().as_millis() as u64;
    Ok(LoadedProofResult {
        witness_ms: 0,
        prove_ms,
        proof_bytes: proof_bytes(&proof)?,
    })
}

/// One presentation with the loaded keys and Prepare data, mirroring the SDK's
/// `present()`: Show witness and prove, then reblind both proofs with the shared
/// blinds. Reblinding consumes its instance and witness, so the loaded Prepare
/// copy is cloned (outside the reblind timer) to keep it reusable.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn present_loaded(documents_path: String) -> Result<PresentResult, ZkProofError> {
    let (prepare_pk, show_pk, data) = {
        let loaded = LOADED.lock().unwrap();
        (
            require(loaded.prepare_pk.as_ref(), "prepare key")?,
            require(loaded.show_pk.as_ref(), "show key")?,
            require(loaded.prepare_reblind.as_ref(), "prepare reblind data")?,
        )
    };
    let mut rss_per_step = true;
    let total = std::time::Instant::now();

    let (proved, show_prove_ms, peak_show_prove) = measure(&mut rss_per_step, || {
        prove_show_in_memory(&documents_path, &show_pk)
    });
    let (_, show_instance, show_witness) = proved?;

    if !reset_peak_rss() {
        rss_per_step = false;
    }
    let (instance, witness) = (data.instance.clone(), data.witness.clone());
    let start = std::time::Instant::now();
    let (prepare_proof, _, _) =
        reblind_in_memory(&prepare_pk, instance, witness, &data.blinds).map_err(proving_failed)?;
    let prepare_reblind_ms = start.elapsed().as_millis() as u64;
    let peak_prepare_reblind = read_peak_rss_kb();

    let (reblinded, show_reblind_ms, peak_show_reblind) = measure(&mut rss_per_step, || {
        reblind_in_memory(&show_pk, show_instance, show_witness, &data.blinds)
    });
    let (show_proof, _, _) = reblinded.map_err(proving_failed)?;

    Ok(PresentResult {
        show_prove_ms,
        prepare_reblind_ms,
        show_reblind_ms,
        total_ms: total.elapsed().as_millis() as u64,
        peak_rss_show_prove_kb: peak_show_prove,
        peak_rss_prepare_reblind_kb: peak_prepare_reblind,
        peak_rss_show_reblind_kb: peak_show_reblind,
        peak_rss_kb: max_peak(&[peak_show_prove, peak_prepare_reblind, peak_show_reblind]),
        rss_per_step,
        prepare_proof_bytes: proof_bytes(&prepare_proof)?,
        show_proof_bytes: proof_bytes(&show_proof)?,
    })
}

// ============================================================================
// Benchmark Operations
// ============================================================================

/// Run complete benchmark pipeline for both JWT and Show circuits
/// Executes all 9 steps: setup, prove, reblind, and verify for both circuits
/// Returns comprehensive timing, peak memory and size metrics
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn run_complete_benchmark(
    documents_path: String,
) -> Result<BenchmarkResults, ZkProofError> {
    run_complete_benchmark_with(documents_path, 0, false)
}

/// Run the complete benchmark on a dedicated rayon pool.
/// `num_threads` 0 means rayon's default, or the big-core count when pinning.
/// `pin_big_cores` restricts pool threads to the big cores (Android/Linux only).
/// (0, false) uses the global pool.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn run_complete_benchmark_with(
    documents_path: String,
    num_threads: u32,
    pin_big_cores: bool,
) -> Result<BenchmarkResults, ZkProofError> {
    if num_threads == 0 && !pin_big_cores {
        return benchmark_pipeline(&documents_path);
    }

    let big_cores = if pin_big_cores {
        classify_big_cores(&read_cpu_max_freqs_khz())
    } else {
        Vec::new()
    };
    let pinned = Arc::new(AtomicUsize::new(0));
    let handler_pinned = Arc::clone(&pinned);
    let end_check_cores = big_cores.clone();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(pool_size(num_threads, big_cores.len()))
        .start_handler(move |_| {
            if pin_current_thread(&big_cores) {
                handler_pinned.fetch_add(1, Ordering::SeqCst);
            }
        })
        .build()
        .map_err(|e| ZkProofError::IoError {
            message: format!("Failed to build thread pool: {}", e),
        })?;
    // Start handlers run on the worker threads; broadcast returns only after
    // every worker has passed its handler, so the count below is final.
    pool.broadcast(|_| ());
    let mut results = pool.install(|| benchmark_pipeline(&documents_path))?;
    results.pinned_threads = pinned.load(Ordering::SeqCst) as u32;
    results.pinned_threads_end = pool
        .broadcast(|_| affinity_is(&end_check_cores))
        .into_iter()
        .filter(|&ok| ok)
        .count() as u32;
    Ok(results)
}

/// 0 lets rayon pick its default; with pinning, 0 means one thread per big core.
fn pool_size(num_threads: u32, big_cores: usize) -> usize {
    match (num_threads, big_cores) {
        (0, n) => n,
        (k, _) => k as usize,
    }
}

fn benchmark_pipeline(documents_path: &str) -> Result<BenchmarkResults, ZkProofError> {
    let mut rss_per_step = true;
    let config = make_config(documents_path);
    let jwt_input = PathBuf::from(documents_path).join(format!("{}_input.json", JWT_CIRCUIT_NAME));
    let show_input =
        PathBuf::from(documents_path).join(format!("{}_input.json", SHOW_CIRCUIT_NAME));

    // Note: While circuits have 98 shared values (2 keybindings + 96 claim scalars),
    // Hyrax batches all these into a single commitment point.
    // num_shared_rows() returns the number of Hyrax commitment points, not individual scalars.
    const NUM_SHARED: usize = 1;

    // Step 1: Setup JWT Circuit
    let jwt_circuit = PrepareCircuit::new(config.clone(), Some(jwt_input.clone()));
    let ((jwt_pk, jwt_vk), jwt_setup_ms, peak_rss_jwt_setup_kb) =
        measure(&mut rss_per_step, || setup_circuit_keys_no_save(jwt_circuit));

    // Save JWT keys after timing
    save_keys(
        config.key_path(PREPARE_PROVING_KEY),
        config.key_path(PREPARE_VERIFYING_KEY),
        &jwt_pk,
        &jwt_vk,
    )
    .map_err(|e| ZkProofError::IoError {
        message: format!("Failed to save JWT keys: {}", e),
    })?;

    // Step 2: Setup Show Circuit
    let show_circuit = ShowCircuit::new(config.clone(), Some(show_input.clone()));
    let ((show_pk, show_vk), show_setup_ms, peak_rss_show_setup_kb) =
        measure(&mut rss_per_step, || setup_circuit_keys_no_save(show_circuit));

    // Save Show keys after timing
    save_keys(
        config.key_path(SHOW_PROVING_KEY),
        config.key_path(SHOW_VERIFYING_KEY),
        &show_pk,
        &show_vk,
    )
    .map_err(|e| ZkProofError::IoError {
        message: format!("Failed to save Show keys: {}", e),
    })?;

    // Step 3: Generate Shared Blinds
    let ((), generate_blinds_ms, peak_rss_generate_blinds_kb) = measure(&mut rss_per_step, || {
        gen_shared_blinds::<E>(config.artifact_path(SHARED_BLINDS), NUM_SHARED)
    });

    // Step 4: Prove JWT Circuit
    let ((), prove_jwt_ms, peak_rss_prove_jwt_kb) = measure(&mut rss_per_step, || {
        let jwt_circuit = PrepareCircuit::new(config.clone(), Some(jwt_input));
        prove_circuit_with_pk(
            jwt_circuit,
            &jwt_pk,
            config.artifact_path(PREPARE_INSTANCE),
            config.artifact_path(PREPARE_WITNESS),
            config.artifact_path(PREPARE_PROOF),
        )
    });

    // Step 5: Reblind JWT
    // Load data before timing (file I/O should not be part of reblind benchmark)
    let jwt_instance = load_instance(config.artifact_path(PREPARE_INSTANCE)).map_err(|e| {
        ZkProofError::FileNotFound {
            message: format!("Failed to load jwt instance: {}", e),
        }
    })?;
    let jwt_witness = load_witness(config.artifact_path(PREPARE_WITNESS)).map_err(|e| {
        ZkProofError::FileNotFound {
            message: format!("Failed to load jwt witness: {}", e),
        }
    })?;
    let shared_blinds =
        load_shared_blinds::<E>(config.artifact_path(SHARED_BLINDS)).map_err(|e| {
            ZkProofError::FileNotFound {
                message: format!("Failed to load shared blinds: {}", e),
            }
        })?;

    let ((), reblind_jwt_ms, peak_rss_reblind_jwt_kb) = measure(&mut rss_per_step, || {
        reblind_with_loaded_data(
            &jwt_pk,
            jwt_instance,
            jwt_witness,
            &shared_blinds,
            config.artifact_path(PREPARE_INSTANCE),
            config.artifact_path(PREPARE_WITNESS),
            config.artifact_path(PREPARE_PROOF),
        )
    });

    // Step 6: Prove Show Circuit
    let ((), prove_show_ms, peak_rss_prove_show_kb) = measure(&mut rss_per_step, || {
        let show_circuit = ShowCircuit::new(config.clone(), Some(show_input));
        prove_circuit_with_pk(
            show_circuit,
            &show_pk,
            config.artifact_path(SHOW_INSTANCE),
            config.artifact_path(SHOW_WITNESS),
            config.artifact_path(SHOW_PROOF),
        )
    });

    // Step 7: Reblind Show
    // Load data before timing (file I/O should not be part of reblind benchmark)
    let show_instance = load_instance(config.artifact_path(SHOW_INSTANCE)).map_err(|e| {
        ZkProofError::FileNotFound {
            message: format!("Failed to load show instance: {}", e),
        }
    })?;
    let show_witness = load_witness(config.artifact_path(SHOW_WITNESS)).map_err(|e| {
        ZkProofError::FileNotFound {
            message: format!("Failed to load show witness: {}", e),
        }
    })?;
    // Reuse shared_blinds from JWT step (already loaded)

    let ((), reblind_show_ms, peak_rss_reblind_show_kb) = measure(&mut rss_per_step, || {
        reblind_with_loaded_data(
            &show_pk,
            show_instance,
            show_witness,
            &shared_blinds,
            config.artifact_path(SHOW_INSTANCE),
            config.artifact_path(SHOW_WITNESS),
            config.artifact_path(SHOW_PROOF),
        )
    });

    // Step 8: Verify JWT
    // Load proof before timing (file I/O should not be part of verify benchmark)
    let jwt_proof = load_proof(config.artifact_path(PREPARE_PROOF)).map_err(|e| {
        ZkProofError::FileNotFound {
            message: format!("Failed to load jwt proof: {}", e),
        }
    })?;

    let (_, verify_jwt_ms, peak_rss_verify_jwt_kb) = measure(&mut rss_per_step, || {
        verify_circuit_with_loaded_data(&jwt_proof, &jwt_vk)
    });

    // Step 9: Verify Show
    // Load proof before timing (file I/O should not be part of verify benchmark)
    let show_proof =
        load_proof(config.artifact_path(SHOW_PROOF)).map_err(|e| ZkProofError::FileNotFound {
            message: format!("Failed to load show proof: {}", e),
        })?;

    let (_, verify_show_ms, peak_rss_verify_show_kb) = measure(&mut rss_per_step, || {
        verify_circuit_with_loaded_data(&show_proof, &show_vk)
    });

    // Measure file sizes
    let jwt_proving_key_bytes = get_proof_size(&config.key_path(PREPARE_PROVING_KEY))?;
    let jwt_verifying_key_bytes = get_proof_size(&config.key_path(PREPARE_VERIFYING_KEY))?;
    let show_proving_key_bytes = get_proof_size(&config.key_path(SHOW_PROVING_KEY))?;
    let show_verifying_key_bytes = get_proof_size(&config.key_path(SHOW_VERIFYING_KEY))?;
    let jwt_proof_bytes = get_proof_size(&config.artifact_path(PREPARE_PROOF))?;
    let show_proof_bytes = get_proof_size(&config.artifact_path(SHOW_PROOF))?;
    let jwt_witness_bytes = get_proof_size(&config.artifact_path(PREPARE_WITNESS))?;
    let show_witness_bytes = get_proof_size(&config.artifact_path(SHOW_WITNESS))?;

    Ok(BenchmarkResults {
        jwt_setup_ms,
        show_setup_ms,
        generate_blinds_ms,
        prove_jwt_ms,
        reblind_jwt_ms,
        prove_show_ms,
        reblind_show_ms,
        verify_jwt_ms,
        verify_show_ms,
        peak_rss_jwt_setup_kb,
        peak_rss_show_setup_kb,
        peak_rss_generate_blinds_kb,
        peak_rss_prove_jwt_kb,
        peak_rss_reblind_jwt_kb,
        peak_rss_prove_show_kb,
        peak_rss_reblind_show_kb,
        peak_rss_verify_jwt_kb,
        peak_rss_verify_show_kb,
        rss_per_step,
        pool_threads: rayon::current_num_threads() as u32,
        pinned_threads: 0,
        pinned_threads_end: 0,
        jwt_proving_key_bytes,
        jwt_verifying_key_bytes,
        show_proving_key_bytes,
        show_verifying_key_bytes,
        jwt_proof_bytes,
        show_proof_bytes,
        jwt_witness_bytes,
        show_witness_bytes,
    })
}

// ============================================================================
// Inspection Operations
// ============================================================================

/// Get the shared witness commitment for a circuit
/// Returns hex-encoded commitment that links JWT and Show proofs
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn get_comm_w_shared(
    documents_path: String,
    circuit_type: String,
) -> Result<String, ZkProofError> {
    let config = make_config(&documents_path);
    let instance_path = match circuit_type.as_str() {
        "jwt" => config.artifact_path(PREPARE_INSTANCE),
        "show" => config.artifact_path(SHOW_INSTANCE),
        _ => {
            return Err(ZkProofError::InvalidInput {
                message: format!(
                    "Invalid circuit_type '{}'. Must be 'jwt' or 'show'",
                    circuit_type
                ),
            })
        }
    };

    extract_comm_w_shared(&instance_path)
}

// ============================================================================
// Internal Helper Functions
// ============================================================================

/// Extract comm_W_shared from a saved instance file
fn extract_comm_w_shared(
    instance_path: impl AsRef<std::path::Path>,
) -> Result<String, ZkProofError> {
    let instance_path = instance_path.as_ref();
    let instance = load_instance(instance_path).map_err(|e| ZkProofError::FileNotFound {
        message: format!(
            "Failed to load instance from '{}': {}",
            instance_path.display(),
            e
        ),
    })?;

    // Convert comm_W_shared to hex string
    let comm_w_shared_hex = format!("{:?}", instance.comm_W_shared);
    Ok(comm_w_shared_hex)
}

/// Get the size of a proof file in bytes
fn get_proof_size(proof_path: impl AsRef<std::path::Path>) -> Result<u64, ZkProofError> {
    let proof_path = proof_path.as_ref();
    let metadata = std::fs::metadata(proof_path).map_err(|e| ZkProofError::FileNotFound {
        message: format!(
            "Failed to get proof size from '{}': {}",
            proof_path.display(),
            e
        ),
    })?;

    Ok(metadata.len())
}

// ============================================================================
// Device Profiling
// ============================================================================

/// Parse a "Key:   12345 kB" line out of /proc/self/status or /proc/meminfo.
fn parse_status_kb(text: &str, key: &str) -> Option<u64> {
    text.lines()
        .find_map(|l| l.strip_prefix(key))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
}

fn parse_mem_available_kb(meminfo: &str) -> Option<u64> {
    parse_status_kb(meminfo, "MemAvailable:")
}

/// MemAvailable in KiB, or 0 where /proc/meminfo is unavailable.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn mem_available_kb() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| parse_mem_available_kb(&s))
        .unwrap_or(0)
}

#[cfg(any(target_os = "linux", target_os = "android", test))]
fn parse_vmhwm_kb(status: &str) -> Option<u64> {
    parse_status_kb(status, "VmHWM:")
}

#[cfg(any(target_os = "linux", target_os = "android", test))]
fn parse_vmrss_kb(status: &str) -> Option<u64> {
    parse_status_kb(status, "VmRSS:")
}

/// Cores above the lowest frequency tier are "big"; with a single tier (or no
/// readable frequencies) every core counts as big. Unreadable cores in a mixed
/// layout are not big.
fn classify_big_cores(max_freqs_khz: &[Option<u64>]) -> Vec<usize> {
    let lowest = max_freqs_khz.iter().flatten().min();
    let highest = max_freqs_khz.iter().flatten().max();
    if lowest == highest {
        return (0..max_freqs_khz.len()).collect();
    }
    max_freqs_khz
        .iter()
        .enumerate()
        .filter(|(_, f)| f.is_some_and(|f| Some(&f) > lowest))
        .map(|(i, _)| i)
        .collect()
}

fn read_cpu_max_freqs_khz() -> Vec<Option<u64>> {
    (0..)
        .map(|n| format!("/sys/devices/system/cpu/cpu{}", n))
        .take_while(|dir| Path::new(dir).exists())
        .map(|dir| {
            std::fs::read_to_string(format!("{}/cpufreq/cpuinfo_max_freq", dir))
                .ok()
                .and_then(|v| v.trim().parse().ok())
        })
        .collect()
}

/// True when both lists name the same CPUs, ignoring order and duplicates.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn affinity_matches(requested: &[usize], effective: &[usize]) -> bool {
    let normalize = |cpus: &[usize]| {
        let mut v = cpus.to_vec();
        v.sort_unstable();
        v.dedup();
        v
    };
    normalize(requested) == normalize(effective)
}

/// Whether the calling thread's effective affinity mask equals `cores`.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn affinity_is(cores: &[usize]) -> bool {
    if cores.is_empty() {
        return false;
    }
    // SAFETY: cpu_set_t is plain data, valid when zeroed; the pointer and size
    // passed to sched_getaffinity describe this local value.
    let effective = unsafe {
        let mut got: libc::cpu_set_t = std::mem::zeroed();
        if libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut got) != 0 {
            tracing::warn!("sched_getaffinity failed: {}", std::io::Error::last_os_error());
            return false;
        }
        (0..libc::CPU_SETSIZE as usize)
            .filter(|&c| libc::CPU_ISSET(c, &got))
            .collect::<Vec<_>>()
    };
    let matches = affinity_matches(cores, &effective);
    if !matches {
        tracing::warn!("affinity is {:?}, requested {:?}", effective, cores);
    }
    matches
}

/// Pins the calling thread to `cores` and reads the mask back: the kernel
/// intersects the request with the app's cpuset, so a successful call alone
/// does not prove the thread landed on the requested cores.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn pin_current_thread(cores: &[usize]) -> bool {
    if cores.is_empty() {
        return false;
    }
    // SAFETY: cpu_set_t is plain data, valid when zeroed; the pointer and size
    // passed to sched_setaffinity describe this local value.
    let rc = unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        for &c in cores {
            libc::CPU_SET(c, &mut set);
        }
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set)
    };
    if rc != 0 {
        tracing::warn!("sched_setaffinity failed: {}", std::io::Error::last_os_error());
        return false;
    }
    affinity_is(cores)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn pin_current_thread(_cores: &[usize]) -> bool {
    false
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn affinity_is(_cores: &[usize]) -> bool {
    false
}

/// Resets the kernel's VmHWM to the current RSS. Returns false when unsupported
/// or denied.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn reset_peak_rss() -> bool {
    cfg!(any(target_os = "linux", target_os = "android"))
        && std::fs::write("/proc/self/clear_refs", "5").is_ok()
}

/// Peak resident set size of this process in KiB since the last reset.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn peak_rss_kb() -> u64 {
    read_peak_rss_kb()
}

/// Current resident set size in KiB, or 0 where /proc is unavailable.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn current_rss_kb() -> u64 {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| parse_vmrss_kb(&s))
            .unwrap_or(0)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        0
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_peak_rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| parse_vmhwm_kb(&s))
        .unwrap_or(0)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn read_peak_rss_kb() -> u64 {
    // SAFETY: rusage is plain data and getrusage fills the zeroed local.
    let max_rss = unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut usage);
        usage.ru_maxrss as u64
    };
    // ru_maxrss is bytes on Apple platforms, KiB elsewhere.
    if cfg!(target_vendor = "apple") {
        max_rss / 1024
    } else {
        max_rss
    }
}

#[cfg(not(unix))]
fn read_peak_rss_kb() -> u64 {
    0
}

/// Runs `f`, returning its output, elapsed ms and the peak RSS reached during it.
/// Clears `per_step` if the peak could not be reset beforehand.
fn measure<T>(per_step: &mut bool, f: impl FnOnce() -> T) -> (T, u64, u64) {
    if !reset_peak_rss() {
        *per_step = false;
    }
    let start = std::time::Instant::now();
    let out = f();
    let ms = start.elapsed().as_millis() as u64;
    (out, ms, read_peak_rss_kb())
}

#[cfg(target_os = "android")]
fn android_prop(name: &str) -> String {
    std::process::Command::new("getprop")
        .arg(name)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

#[cfg(not(target_os = "android"))]
fn android_prop(_name: &str) -> String {
    String::new()
}

/// Compact JSON describing the device: SoC, model, RAM, per-core max
/// frequencies, the big-core set and rayon's default thread count.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn device_profile() -> String {
    let freqs = read_cpu_max_freqs_khz();
    let mem_total_kb = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| parse_status_kb(&s, "MemTotal:"))
        .unwrap_or(0);
    serde_json::json!({
        "soc_model": android_prop("ro.soc.model"),
        "soc_manufacturer": android_prop("ro.soc.manufacturer"),
        "product_model": android_prop("ro.product.model"),
        "manufacturer": android_prop("ro.product.manufacturer"),
        "android_sdk": android_prop("ro.build.version.sdk"),
        "mem_total_kb": mem_total_kb,
        "mem_available_kb": mem_available_kb(),
        "cpu_max_freq_khz": freqs,
        "big_cores": classify_big_cores(&freqs),
        "rayon_default_threads": rayon::current_num_threads(),
    })
    .to_string()
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
    fn test_path_config_mobile() {
        let config = make_config("/app/Documents");
        assert_eq!(
            config.key_path(PREPARE_PROVING_KEY),
            PathBuf::from("/app/Documents/keys/prepare_proving.key")
        );
        assert_eq!(
            config.artifact_path(PREPARE_PROOF),
            PathBuf::from("/app/Documents/keys/prepare_proof.bin")
        );
    }

    #[test]
    fn test_make_config_uses_2k() {
        let config = make_config("/docs");
        assert_eq!(config.circuit_size, CircuitSize::Kb2);
        assert!(config.is_mobile);
    }

    #[test]
    fn test_invalid_circuit_type() {
        let result = get_comm_w_shared(".".to_string(), "invalid".to_string());
        assert!(matches!(result, Err(ZkProofError::InvalidInput { .. })));
    }

    #[test]
    fn test_parse_vmhwm_kb() {
        let status = "Name:\tflutter\nVmPeak:\t 3000000 kB\nVmHWM:\t 2345678 kB\nVmRSS:\t 100 kB\n";
        assert_eq!(parse_vmhwm_kb(status), Some(2345678));
    }

    #[test]
    fn test_parse_vmhwm_kb_missing_or_malformed() {
        assert_eq!(parse_vmhwm_kb("VmRSS:\t 100 kB\n"), None);
        assert_eq!(parse_vmhwm_kb("VmHWM:\t lots kB\n"), None);
        assert_eq!(parse_vmhwm_kb(""), None);
    }

    #[test]
    fn test_affinity_matches() {
        assert!(affinity_matches(&[4, 5, 6, 7], &[7, 6, 5, 4]));
        assert!(affinity_matches(&[2, 2, 3], &[3, 2]));
        // The kernel narrowed the mask to the app's cpuset.
        assert!(!affinity_matches(&[4, 5, 6, 7], &[4, 5]));
        assert!(!affinity_matches(&[4, 5], &[0, 1, 2, 3, 4, 5]));
    }

    #[test]
    fn test_pool_size() {
        assert_eq!(pool_size(0, 0), 0);
        assert_eq!(pool_size(0, 4), 4);
        assert_eq!(pool_size(3, 0), 3);
        assert_eq!(pool_size(3, 4), 3);
    }

    #[test]
    fn test_parse_vmrss_kb() {
        let status = "VmHWM:\t 2345678 kB\nVmRSS:\t 1234 kB\n";
        assert_eq!(parse_vmrss_kb(status), Some(1234));
        assert_eq!(parse_vmrss_kb("VmHWM:\t 5 kB\n"), None);
    }

    #[test]
    fn test_parse_meminfo_total_kb() {
        let meminfo = "MemTotal:        5890204 kB\nMemFree:          123 kB\n";
        assert_eq!(parse_status_kb(meminfo, "MemTotal:"), Some(5890204));
    }

    #[test]
    fn test_big_cores_one_three_four() {
        let f = |khz| Some(khz);
        let freqs = [
            f(1_800_000), f(1_800_000), f(1_800_000), f(1_800_000),
            f(2_400_000), f(2_400_000), f(2_400_000), f(3_000_000),
        ];
        assert_eq!(classify_big_cores(&freqs), vec![4, 5, 6, 7]);
    }

    #[test]
    fn test_big_cores_two_six() {
        let freqs = [
            Some(2_000_000), Some(2_000_000), Some(2_000_000), Some(2_000_000),
            Some(2_000_000), Some(2_000_000), Some(2_800_000), Some(2_800_000),
        ];
        assert_eq!(classify_big_cores(&freqs), vec![6, 7]);
    }

    #[test]
    fn test_big_cores_all_equal_or_unreadable() {
        assert_eq!(classify_big_cores(&[Some(2_000_000); 4]), vec![0, 1, 2, 3]);
        assert_eq!(classify_big_cores(&[None, None, None]), vec![0, 1, 2]);
        assert!(classify_big_cores(&[]).is_empty());
    }

    #[test]
    fn test_big_cores_skips_unreadable_in_mixed_layout() {
        let freqs = [Some(1_500_000), None, Some(2_500_000)];
        assert_eq!(classify_big_cores(&freqs), vec![2]);
    }

    #[test]
    fn test_parse_status_kb_separators_and_suffix() {
        assert_eq!(parse_status_kb("VmHWM:\t42 kB\n", "VmHWM:"), Some(42));
        assert_eq!(parse_status_kb("VmHWM:     42 kB\n", "VmHWM:"), Some(42));
        assert_eq!(parse_status_kb("VmHWM:42 kB\n", "VmHWM:"), Some(42));
        assert_eq!(parse_status_kb("VmHWM:\t42\n", "VmHWM:"), Some(42));
        assert_eq!(parse_status_kb("VmHWM:\t42", "VmHWM:"), Some(42));
        assert_eq!(parse_status_kb("VmHWM:\t42 MB\n", "VmHWM:"), Some(42));
    }

    #[test]
    fn test_parse_status_kb_key_edge_cases() {
        // Different key sharing a prefix, and an empty value.
        assert_eq!(parse_vmhwm_kb("VmHWMx:\t5 kB\n"), None);
        assert_eq!(parse_vmhwm_kb("VmHWM:\n"), None);
        assert_eq!(parse_vmhwm_kb("VmHWM:\t-5 kB\n"), None);
        assert_eq!(parse_vmhwm_kb("  VmHWM:\t5 kB\n"), None);
        // Key must be at line start; a longer key does not shadow the real one.
        assert_eq!(parse_vmhwm_kb("VmHWMx:\t5 kB\nVmHWM:\t7 kB\n"), Some(7));
        assert_eq!(parse_vmhwm_kb("VmHWM:\t7 kB\r\n"), Some(7));
        // First matching line wins, even when it is malformed.
        assert_eq!(parse_vmhwm_kb("VmHWM:\tx kB\nVmHWM:\t7 kB\n"), None);
        assert_eq!(parse_vmhwm_kb("VmHWM:\t99999999999999999999999 kB\n"), None);
        assert_eq!(parse_vmrss_kb("VmRSS:\t0 kB\n"), Some(0));
    }

    #[test]
    fn test_big_cores_one_three_four_prime_first() {
        let freqs = [
            Some(3_000_000), Some(2_000_000), Some(2_000_000), Some(2_000_000),
            Some(1_000_000), Some(1_000_000), Some(1_000_000), Some(1_000_000),
        ];
        assert_eq!(classify_big_cores(&freqs), vec![0, 1, 2, 3]);
    }

    #[test]
    fn test_big_cores_tensor_g5_one_five_two() {
        let freqs = [
            Some(3_800_000), Some(3_050_000), Some(3_050_000), Some(3_050_000),
            Some(3_050_000), Some(3_050_000), Some(2_200_000), Some(2_200_000),
        ];
        assert_eq!(classify_big_cores(&freqs), vec![0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_big_cores_single_core_and_one_tier_with_unreadable() {
        assert_eq!(classify_big_cores(&[Some(1_000_000)]), vec![0]);
        assert_eq!(classify_big_cores(&[None]), vec![0]);
        // One readable tier plus unreadable cores counts as a single tier.
        assert_eq!(classify_big_cores(&[Some(2_000_000), None]), vec![0, 1]);
    }

    #[test]
    fn test_big_cores_leading_unreadable_and_unsorted() {
        let freqs = [None, Some(2_800_000), Some(1_500_000), Some(2_800_000)];
        assert_eq!(classify_big_cores(&freqs), vec![1, 3]);
    }

    #[test]
    fn test_device_profile_is_valid_json_with_expected_keys() {
        let v: serde_json::Value = serde_json::from_str(&device_profile()).expect("valid JSON");
        for k in [
            "soc_model", "soc_manufacturer", "product_model", "manufacturer", "android_sdk",
        ] {
            #[cfg(not(target_os = "android"))]
            assert_eq!(v[k], serde_json::json!(""), "{k}");
            #[cfg(target_os = "android")]
            assert!(v[k].is_string(), "{k}");
        }
        assert!(v["mem_total_kb"].is_u64());
        let freqs = v["cpu_max_freq_khz"].as_array().expect("freqs array");
        let big = v["big_cores"].as_array().expect("big_cores array");
        assert!(big.iter().all(|i| i.as_u64().is_some()));
        assert!(freqs.iter().all(|f| f.is_null() || f.is_u64()));
        assert!(v["rayon_default_threads"].as_u64().unwrap() >= 1);
        // No cpufreq sysfs off Linux/Android.
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            assert!(freqs.is_empty());
            assert!(big.is_empty());
            assert_eq!(v["mem_total_kb"], 0);
        }
    }

    #[test]
    fn test_parse_meminfo_available_kb() {
        let meminfo = "MemTotal:        5890204 kB\nMemFree:          123 kB\nMemAvailable:    2048000 kB\n";
        assert_eq!(parse_mem_available_kb(meminfo), Some(2048000));
        assert_eq!(parse_mem_available_kb("MemTotal:  1 kB\n"), None);
        // A key that merely shares the prefix must not match.
        assert_eq!(parse_mem_available_kb("MemAvailableX: 5 kB\n"), None);
    }

    #[test]
    fn test_device_profile_has_mem_available() {
        let v: serde_json::Value = serde_json::from_str(&device_profile()).expect("valid JSON");
        assert!(v["mem_available_kb"].is_u64());
    }

    #[test]
    fn test_load_key_missing_file_is_file_not_found() {
        let r = load_prepare_key("/nonexistent/prepare.key".to_string());
        assert!(matches!(r, Err(ZkProofError::FileNotFound { .. })));
        let r = load_show_key("/nonexistent/show.key".to_string());
        assert!(matches!(r, Err(ZkProofError::FileNotFound { .. })));
    }

    #[test]
    fn test_prove_without_loaded_key_requires_setup() {
        let _guard = LOADED_LOCK.lock().unwrap();
        clear_loaded_for_test();
        assert!(matches!(
            prove_prepare_loaded("/docs".to_string()),
            Err(ZkProofError::SetupRequired { .. })
        ));
        assert!(matches!(
            prove_show_loaded("/docs".to_string()),
            Err(ZkProofError::SetupRequired { .. })
        ));
        assert!(matches!(
            present_loaded("/docs".to_string()),
            Err(ZkProofError::SetupRequired { .. })
        ));
    }

    #[test]
    fn test_stage_file_copies_and_creates_parents() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.bin");
        std::fs::write(&src, vec![7u8; 4096]).unwrap();
        let dest = dir.path().join("a/b/dest.bin");
        let n = stage_file(src.to_string_lossy().into(), dest.to_string_lossy().into()).unwrap();
        assert_eq!(n, 4096);
        assert_eq!(std::fs::read(&dest).unwrap(), vec![7u8; 4096]);
    }

    #[test]
    fn test_stage_file_overwrites_existing() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src.bin");
        let dest = dir.path().join("dest.bin");
        std::fs::write(&dest, vec![1u8; 9000]).unwrap();
        std::fs::write(&src, b"new").unwrap();
        stage_file(src.to_string_lossy().into(), dest.to_string_lossy().into()).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"new");
    }

    #[test]
    fn test_stage_file_missing_source() {
        let r = stage_file("/nonexistent/src.bin".into(), "/tmp/never.bin".into());
        assert!(matches!(r, Err(ZkProofError::FileNotFound { .. })));
    }

    #[test]
    fn test_zk_error_message_is_display_text() {
        let e = ZkProofError::FileNotFound { message: "no key".into() };
        assert_eq!(zk_error_message(&e), "File not found: no key");
    }

    #[test]
    fn test_max_peak() {
        assert_eq!(max_peak(&[10, 30, 20]), 30);
        assert_eq!(max_peak(&[]), 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_rss_helpers_on_macos() {
        assert!(!reset_peak_rss());
        assert!(peak_rss_kb() > 0);
        assert_eq!(current_rss_kb(), 0);
        let mut per_step = true;
        let (out, _ms, peak) = measure(&mut per_step, || 7);
        assert_eq!(out, 7);
        assert!(!per_step);
        assert!(peak > 0);
    }
}

// ============================================================================
// E2E Tests
// ============================================================================

#[cfg(test)]
mod e2e_tests {
    use super::*;
    use std::fs;

    // Absolute path to this crate, set at compile time.
    const CRATE_DIR: &str = env!("CARGO_MANIFEST_DIR");

    fn circom_root() -> PathBuf {
        PathBuf::from(CRATE_DIR)
            .parent()
            .expect("CARGO_MANIFEST_DIR has no parent")
            .join("circom")
    }

    /// Builds a temp directory tree that matches the mobile app's document structure:
    ///
    ///   {temp}/circom/                          ← documents_path passed to Rust FFI
    ///     build/jwt/jwt_js/jwt.r1cs             ← jwt_2k r1cs, using mobile-style name
    ///     build/show/show_js/show.r1cs
    ///     jwt_input.json                        ← 2k JWT inputs (for prove_jwt + run_complete_benchmark)
    ///     show_input.json                       ← show inputs (for prove_show + run_complete_benchmark)
    ///
    /// Returns the documents_path string.
    fn setup_mobile_docs(path: &Path) -> String {
        let docs = path.join("circom");
        let circom = circom_root();

        let jwt_dir = docs.join("build/jwt/jwt_js");
        let show_dir = docs.join("build/show/show_js");
        fs::create_dir_all(&jwt_dir).expect("create jwt dir");
        fs::create_dir_all(&show_dir).expect("create show dir");

        fs::copy(
            circom.join("build/jwt_2k/jwt_2k_js/jwt_2k.r1cs"),
            jwt_dir.join("jwt.r1cs"),
        )
        .expect("copy jwt_2k.r1cs -> jwt.r1cs");
        fs::copy(
            circom.join("build/show/show_js/show.r1cs"),
            show_dir.join("show.r1cs"),
        )
        .expect("copy show.r1cs");

        let jwt_2k_input = circom.join("inputs/jwt/2k/default.json");
        let show_input = circom.join("inputs/show/2k/default.json");

        fs::copy(&jwt_2k_input, docs.join("jwt_input.json"))
            .expect("copy jwt 2k input -> jwt_input.json");
        fs::copy(&show_input, docs.join("show_input.json"))
            .expect("copy show 2k input -> show_input.json");

        docs.to_string_lossy().into_owned()
    }

    /// Full 9-step ZK workflow matching the Flutter app's E2E sequence:
    ///   setup_jwt → setup_show → generate_blinds →
    ///   prove_jwt → reblind_jwt → prove_show → reblind_show →
    ///   verify_jwt → verify_show → comm_W_shared linkage check
    #[test]
    #[ignore = "Long-running e2e (~5 min); run with: cargo test -- --ignored e2e_full_workflow"]
    fn e2e_full_workflow() {
        let temp = tempfile::tempdir().expect("create temp dir");

        let docs = setup_mobile_docs(temp.path());

        // Step 1: Setup JWT keys
        let r = setup_jwt_keys(docs.clone());
        assert!(r.is_ok(), "setup_jwt_keys failed: {:?}", r.err());

        // Step 2: Setup Show keys
        let r = setup_show_keys(docs.clone());
        assert!(r.is_ok(), "setup_show_keys failed: {:?}", r.err());

        // Step 3: Generate shared blinds
        let r = generate_shared_blinds(docs.clone());
        assert!(r.is_ok(), "generate_shared_blinds failed: {:?}", r.err());

        // Step 4: Prove JWT
        let r = prove_jwt(docs.clone());
        assert!(r.is_ok(), "prove_jwt failed: {:?}", r.err());
        let pr = r.unwrap();
        assert!(pr.proof_size_bytes > 0, "proof_size_bytes must be > 0");
        assert!(
            !pr.comm_w_shared.is_empty(),
            "comm_w_shared must be non-empty"
        );

        // Step 5: Reblind JWT — new unlinkable proof, same commitment
        let r = reblind_jwt(docs.clone());
        assert!(r.is_ok(), "reblind_jwt failed: {:?}", r.err());

        // Step 6: Prove Show
        let r = prove_show(docs.clone());
        assert!(r.is_ok(), "prove_show failed: {:?}", r.err());
        let sr = r.unwrap();
        assert!(sr.proof_size_bytes > 0, "show proof_size_bytes must be > 0");
        assert!(
            !sr.comm_w_shared.is_empty(),
            "show comm_w_shared must be non-empty"
        );

        // Step 7: Reblind Show
        let r = reblind_show(docs.clone());
        assert!(r.is_ok(), "reblind_show failed: {:?}", r.err());

        // Step 8: Verify JWT (reblinded proof must pass)
        let r = verify_jwt(docs.clone());
        assert!(r.is_ok(), "verify_jwt failed: {:?}", r.err());
        assert!(r.unwrap(), "jwt proof must verify");

        // Step 9: Verify Show (reblinded proof must pass)
        let r = verify_show(docs.clone());
        assert!(r.is_ok(), "verify_show failed: {:?}", r.err());
        assert!(r.unwrap(), "show proof must verify");

        // Verify get_comm_w_shared works for both circuits.
        // Note: comm_W_shared equality (linkage) requires end-to-end compatible inputs where
        // jwt and show share the same deviceKey and claims. The default test inputs are
        // independent, so we only assert each commitment is readable and non-empty.
        let prep_comm = get_comm_w_shared(docs.clone(), "jwt".to_string())
            .expect("get_comm_w_shared(jwt) must succeed");
        let show_comm = get_comm_w_shared(docs.clone(), "show".to_string())
            .expect("get_comm_w_shared(show) must succeed");
        assert!(
            !prep_comm.is_empty(),
            "jwt comm_W_shared must be non-empty"
        );
        assert!(
            !show_comm.is_empty(),
            "show comm_W_shared must be non-empty"
        );
    }

    /// Complete benchmark pipeline — exercises all 9 operations with precise timing.
    #[test]
    #[ignore = "Long-running e2e (~10 min); run with: cargo test -- --ignored e2e_complete_benchmark"]
    fn e2e_complete_benchmark() {
        let temp = tempfile::tempdir().expect("create temp dir");
        let docs = setup_mobile_docs(temp.path());

        let r = run_complete_benchmark(docs);
        assert!(r.is_ok(), "run_complete_benchmark failed: {:?}", r.err());

        let b = r.unwrap();
        println!(
            "peak_rss_kb setup={}/{} blinds={} prove={}/{} reblind={}/{} verify={}/{} per_step={}",
            b.peak_rss_jwt_setup_kb,
            b.peak_rss_show_setup_kb,
            b.peak_rss_generate_blinds_kb,
            b.peak_rss_prove_jwt_kb,
            b.peak_rss_prove_show_kb,
            b.peak_rss_reblind_jwt_kb,
            b.peak_rss_reblind_show_kb,
            b.peak_rss_verify_jwt_kb,
            b.peak_rss_verify_show_kb,
            b.rss_per_step
        );

        // Long-running operations must record positive ms timings.
        // generate_blinds is sub-millisecond so we only assert it doesn't panic.
        assert!(b.jwt_setup_ms > 0, "jwt_setup_ms must be > 0");
        assert!(b.show_setup_ms > 0, "show_setup_ms must be > 0");
        assert!(b.prove_jwt_ms > 0, "prove_jwt_ms must be > 0");
        assert!(b.reblind_jwt_ms > 0, "reblind_jwt_ms must be > 0");
        assert!(b.prove_show_ms > 0, "prove_show_ms must be > 0");
        assert!(b.reblind_show_ms > 0, "reblind_show_ms must be > 0");
        assert!(b.verify_jwt_ms > 0, "verify_jwt_ms must be > 0");
        assert!(b.verify_show_ms > 0, "verify_show_ms must be > 0");

        // Proving dominates memory; the other steps may legitimately report less.
        assert!(b.peak_rss_prove_jwt_kb > 0, "peak_rss_prove_jwt_kb must be > 0");
        assert!(b.peak_rss_prove_show_kb > 0, "peak_rss_prove_show_kb must be > 0");
        assert!(b.peak_rss_jwt_setup_kb > 0, "peak_rss_jwt_setup_kb must be > 0");

        // All artifacts must be non-empty
        assert!(b.jwt_proof_bytes > 0, "jwt_proof_bytes must be > 0");
        assert!(b.show_proof_bytes > 0, "show_proof_bytes must be > 0");
        assert!(
            b.jwt_proving_key_bytes > 0,
            "jwt_proving_key_bytes must be > 0"
        );
        assert!(
            b.show_proving_key_bytes > 0,
            "show_proving_key_bytes must be > 0"
        );
        assert!(
            b.jwt_witness_bytes > 0,
            "jwt_witness_bytes must be > 0"
        );
        assert!(b.show_witness_bytes > 0, "show_witness_bytes must be > 0");
    }
}

// ============================================================================
// Loaded-key E2E (needs the pushed device files)
// ============================================================================

#[cfg(test)]
mod loaded_key_tests {
    use super::*;
    use ecdsa_spartan2::{load_verifying_key, verify_circuit_with_loaded_data};
    use std::fs;

    /// Proves and reblinds with exactly the files the device gets, and checks
    /// every proof against the original verifying keys. No r1cs is present.
    ///   OPENAC_DEVICE_DIR  the pushed file set (2k_*.key, 2k_shared_blinds.bin, ...)
    ///   OPENAC_VK_DIR      holds 2k_prepare_verifying.key and 2k_show_verifying.key
    #[test]
    #[ignore = "Needs OPENAC_DEVICE_DIR and OPENAC_VK_DIR; run with: cargo test --release -- --ignored loaded_key"]
    fn loaded_key_prove_reblind_verify_without_r1cs() {
        let _guard = LOADED_LOCK.lock().unwrap();
        clear_loaded_for_test();
        let dev = PathBuf::from(std::env::var("OPENAC_DEVICE_DIR").expect("OPENAC_DEVICE_DIR"));
        let vks = PathBuf::from(std::env::var("OPENAC_VK_DIR").expect("OPENAC_VK_DIR"));
        let f = |name: &str| dev.join(name).to_string_lossy().into_owned();

        let circom = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../circom/inputs");
        let docs = tempfile::tempdir().expect("temp dir");
        fs::copy(circom.join("jwt/2k/default.json"), docs.path().join("jwt_input.json")).unwrap();
        fs::copy(circom.join("show/2k/default.json"), docs.path().join("show_input.json")).unwrap();
        let docs_path = docs.path().to_string_lossy().into_owned();

        println!("load prepare {} ms", load_prepare_key(f("2k_prepare_proving.key")).unwrap());
        println!("load show {} ms", load_show_key(f("2k_show_proving.key")).unwrap());
        println!(
            "load reblind data {} ms",
            load_prepare_reblind_data(
                f("2k_prepare_instance.bin"),
                f("2k_prepare_witness.bin"),
                f("2k_shared_blinds.bin"),
            )
            .unwrap()
        );

        let pk_prepare = LOADED.lock().unwrap().prepare_pk.clone().unwrap();
        let pk_show = LOADED.lock().unwrap().show_pk.clone().unwrap();
        let vk_prepare = load_verifying_key(vks.join("2k_prepare_verifying.key")).unwrap();
        let vk_show = load_verifying_key(vks.join("2k_show_verifying.key")).unwrap();

        let ((p, _, _), _) = prove_prepare_in_memory(&docs_path, &pk_prepare).unwrap();
        verify_circuit_with_loaded_data(&p, &vk_prepare);
        let (s, _, _) = prove_show_in_memory(&docs_path, &pk_show).unwrap();
        verify_circuit_with_loaded_data(&s, &vk_show);

        let r = prove_prepare_loaded(docs_path.clone()).unwrap();
        println!("prepare witness_ms={} prove_ms={} proof_bytes={}", r.witness_ms, r.prove_ms, r.proof_bytes);
        let r = prove_show_loaded(docs_path.clone()).unwrap();
        println!("show prove_ms={} proof_bytes={}", r.prove_ms, r.proof_bytes);

        // Two presentations: the second proves the loaded copy survives.
        for _ in 0..2 {
            let r = present_loaded(docs_path.clone()).unwrap();
            println!(
                "present show_prove={} prepare_reblind={} show_reblind={} total={} peak={}",
                r.show_prove_ms, r.prepare_reblind_ms, r.show_reblind_ms, r.total_ms, r.peak_rss_kb
            );
        }

        // Reblind the snapshot's own Prepare data and verify it.
        let data = LOADED.lock().unwrap().prepare_reblind.clone().unwrap();
        let (rp, _, _) = reblind_in_memory(
            &pk_prepare,
            data.instance.clone(),
            data.witness.clone(),
            &data.blinds,
        )
        .unwrap();
        verify_circuit_with_loaded_data(&rp, &vk_prepare);
    }
    /// The desktop `benchmark` flow leaves the post-reblind instance and witness
    /// in keys/, and those cannot be reblinded again (the blind values the
    /// instance names are gone from the witness). This proves Prepare once with
    /// the real key and writes the fresh, reblindable pair into OPENAC_DEVICE_DIR.
    #[test]
    #[ignore = "Writes into OPENAC_DEVICE_DIR; run with: cargo test --release -- --ignored write_reblindable"]
    fn write_reblindable_prepare_data() {
        let _guard = LOADED_LOCK.lock().unwrap();
        clear_loaded_for_test();
        let dev = PathBuf::from(std::env::var("OPENAC_DEVICE_DIR").expect("OPENAC_DEVICE_DIR"));
        let circom = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../circom/inputs");
        let docs = tempfile::tempdir().expect("temp dir");
        fs::copy(circom.join("jwt/2k/default.json"), docs.path().join("jwt_input.json")).unwrap();
        let pk = load_proving_key(dev.join("2k_prepare_proving.key")).unwrap();
        let ((_, instance, witness), _) =
            prove_prepare_in_memory(&docs.path().to_string_lossy(), &pk).unwrap();
        ecdsa_spartan2::setup::save_instance(dev.join("2k_prepare_instance.bin"), &instance).unwrap();
        ecdsa_spartan2::setup::save_witness(dev.join("2k_prepare_witness.bin"), &witness).unwrap();
    }
}

#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;
#[cfg(not(target_arch = "wasm32"))]
use std::{fs::File, path::Path};

// Path is still needed for function signatures used by non-wasm code
#[cfg(target_arch = "wasm32")]
use std::path::Path;

#[cfg(feature = "native-witness")]
use crate::circuits::mdoc_circuit::{
    call_mdoc_witness, MDOC_MAX_CLAIMS, MDOC_MAX_IDENTIFIER_LEN, MDOC_MAX_PREIMAGE_LEN,
    MDOC_MAX_VALUE_LEN,
};
#[cfg(feature = "native-witness")]
use crate::circuits::jsonld_circuit::call_jsonld_witness;
#[cfg(feature = "native-witness")]
use crate::circuits::prepare_circuit::call_jwt_witness;
use crate::utils::parse_witness;
use crate::{paths::PathConfig, Scalar, E};
#[cfg(not(target_arch = "wasm32"))]
use crate::{
    setup::{
        load_instance, load_proof, load_proving_key, load_shared_blinds, load_verifying_key,
        load_witness, save_instance, save_proof, save_shared_blinds, save_witness,
    },
    utils::{
        hashmap_to_json_string, mdoc_hashmap_to_json_string, parse_jsonld_inputs, parse_jwt_inputs,
        parse_mdoc_inputs,
    },
};

use bellpepper_core::SynthesisError;
use ff::{derive::rand_core::OsRng, Field};
#[cfg(not(target_arch = "wasm32"))]
use serde_json::Value;
use spartan2::{
    bellpepper::{solver::SatisfyingAssignment, zk_r1cs::SpartanWitness},
    errors::SpartanError,
    provider::traits::DlogGroup,
    traits::{
        circuit::SpartanCircuit, snark::R1CSSNARKTrait, transcript::TranscriptEngineTrait, Engine,
    },
    zk_spartan::R1CSSNARK,
};
use tracing::info;

/// Run circuit using ZK-Spartan (setup, prepare, prove, verify)
#[cfg(not(target_arch = "wasm32"))]
pub fn run_circuit<C: SpartanCircuit<E> + Clone + std::fmt::Debug>(circuit: C) {
    // SETUP using ZK-Spartan
    let t0 = Instant::now();
    let (pk, vk) = R1CSSNARK::<E>::setup(circuit.clone()).expect("setup failed");
    let setup_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = setup_ms, "ZK-Spartan setup");

    // PREPARE
    let t0 = Instant::now();
    let mut prep_snark =
        R1CSSNARK::<E>::prep_prove(&pk, circuit.clone(), false).expect("prep_prove failed");
    let prep_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = prep_ms, "ZK-Spartan prep_prove");

    // PROVE
    let t0 = Instant::now();
    let proof =
        R1CSSNARK::<E>::prove(&pk, circuit.clone(), &mut prep_snark, false).expect("prove failed");
    let prove_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = prove_ms, "ZK-Spartan prove");

    // VERIFY
    let t0 = Instant::now();
    proof.verify(&vk).expect("verify errored");
    let verify_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = verify_ms, "ZK-Spartan verify");

    // Summary
    info!(
        "ZK-Spartan SUMMARY , setup={} ms, prep_prove={} ms, prove={} ms, verify={} ms",
        setup_ms, prep_ms, prove_ms, verify_ms
    );

    info!("comm_W_shared: {:?}", proof.comm_W_shared());
}

#[cfg(not(target_arch = "wasm32"))]
pub fn generate_shared_blinds<E: Engine>(shared_blinds_path: impl AsRef<Path>, n: usize) {
    let blinds: Vec<_> = (0..n).map(|_| E::Scalar::random(OsRng)).collect();
    if let Err(e) = save_shared_blinds::<E>(shared_blinds_path, &blinds) {
        eprintln!("Failed to save instance: {}", e);
        std::process::exit(1);
    }
}

/// Only run the proving part of the circuit using ZK-Spartan (prep_prove, prove)
#[cfg(not(target_arch = "wasm32"))]
pub fn prove_circuit<C: SpartanCircuit<E> + Clone + std::fmt::Debug>(
    circuit: C,
    pk_path: impl AsRef<Path>,
    instance_path: impl AsRef<Path>,
    witness_path: impl AsRef<Path>,
    proof_path: impl AsRef<Path>,
) {
    let t0 = Instant::now();
    let pk = load_proving_key(&pk_path).expect("load proving key failed");
    let load_pk_ms = t0.elapsed().as_millis();

    info!("ZK-Spartan load proving key: {} ms", load_pk_ms);

    prove_circuit_with_pk(circuit, &pk, instance_path, witness_path, proof_path);
}

/// Only run the proving part of the circuit using ZK-Spartan with a pre-loaded proving key
/// This is useful for benchmarking to exclude file I/O from timing measurements
#[cfg(not(target_arch = "wasm32"))]
pub fn prove_circuit_with_pk<C: SpartanCircuit<E> + Clone + std::fmt::Debug>(
    circuit: C,
    pk: &<R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey,
    instance_path: impl AsRef<Path>,
    witness_path: impl AsRef<Path>,
    proof_path: impl AsRef<Path>,
) {
    let t0 = Instant::now();
    let mut prep_snark =
        R1CSSNARK::<E>::prep_prove(&pk, circuit.clone(), false).expect("prep_prove failed");
    let prep_ms = t0.elapsed().as_millis();
    info!("ZK-Spartan prep_prove: {} ms", prep_ms);

    let t0 = Instant::now();
    let mut transcript = <E as Engine>::TE::new(b"R1CSSNARK");
    transcript.absorb(b"vk", &pk.vk_digest);

    let public_values = SpartanCircuit::<E>::public_values(&circuit)
        .map_err(|e| SpartanError::SynthesisError {
            reason: format!("Circuit does not provide public IO: {e}"),
        })
        .unwrap();

    // absorb the public values into the transcript
    transcript.absorb(b"public_values", &public_values.as_slice());

    let (instance, witness) = SatisfyingAssignment::r1cs_instance_and_witness(
        &mut prep_snark.ps,
        &pk.S,
        &pk.ck,
        &circuit,
        false,
        &mut transcript,
    )
    .unwrap();

    // generate a witness and proof
    let res = R1CSSNARK::<E>::prove_inner(&pk, &instance, &witness, &mut transcript).unwrap();
    let prove_ms = t0.elapsed().as_millis();

    info!("ZK-Spartan prove: {} ms", prove_ms);

    let total_ms = prep_ms + prove_ms;

    info!(
        "ZK-Spartan prep_prove: ({} ms) + prove: ({} ms) = TOTAL: {} ms",
        prep_ms, prove_ms, total_ms
    );

    // Save the instance to file
    if let Err(e) = save_instance(instance_path, &instance) {
        eprintln!("Failed to save instance: {}", e);
        std::process::exit(1);
    }

    // Save the witness to file
    if let Err(e) = save_witness(witness_path, &witness) {
        eprintln!("Failed to save witness: {}", e);
        std::process::exit(1);
    }

    // Save the proof to file
    if let Err(e) = save_proof(proof_path, &res) {
        eprintln!("Failed to save proof: {}", e);
        std::process::exit(1);
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn reblind(
    pk_path: impl AsRef<Path>,
    instance_path: impl AsRef<Path>,
    witness_path: impl AsRef<Path>,
    proof_path: impl AsRef<Path>,
    shared_blinds_path: impl AsRef<Path>,
) {
    let pk = load_proving_key(&pk_path).expect("load proving key failed");
    let instance = load_instance(&instance_path).expect("load instance failed");
    let witness = load_witness(&witness_path).expect("load witness failed");
    let randomness =
        load_shared_blinds::<E>(&shared_blinds_path).expect("load shared_blinds failed");

    reblind_with_loaded_data(
        &pk,
        instance,
        witness,
        &randomness,
        instance_path,
        witness_path,
        proof_path,
    );
}

/// Reblind with pre-loaded data - useful for benchmarking to exclude file I/O.
///
/// Uses the public values stored in the instance (from the original proving step)
/// rather than re-deriving them from the circuit.
#[cfg(not(target_arch = "wasm32"))]
pub fn reblind_with_loaded_data(
    pk: &<R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey,
    instance: spartan2::r1cs::SplitR1CSInstance<E>,
    witness: spartan2::r1cs::R1CSWitness<E>,
    randomness: &[<E as Engine>::Scalar],
    instance_path: impl AsRef<Path>,
    witness_path: impl AsRef<Path>,
    proof_path: impl AsRef<Path>,
) {
    assert_eq!(randomness.len(), instance.num_shared_rows());

    // Reblind instance and witness
    let mut reblind_transcript = <E as Engine>::TE::new(b"R1CSSNARK");
    reblind_transcript.absorb(b"vk", &pk.vk_digest);

    // Use the public values stored in the instance from the original proving step.
    let public_values = instance.get_public_values();

    // absorb the public values into the reblind_transcript
    reblind_transcript.absorb(b"public_values", &public_values);

    let (new_instance, new_witness) = SatisfyingAssignment::reblind_r1cs_instance_and_witness(
        &randomness,
        instance,
        witness,
        &pk.ck,
        &mut reblind_transcript,
    )
    .unwrap();

    println!(
        "new instance: {:?}",
        new_instance
            .clone()
            .comm_W_shared
            .map(|v| v.comm.iter().for_each(|v| println!("v: {:?}", v.affine())))
    );

    // generate a witness and proof
    let res =
        R1CSSNARK::<E>::prove_inner(&pk, &new_instance, &new_witness, &mut reblind_transcript)
            .unwrap();

    // Save the instance to file
    if let Err(e) = save_instance(instance_path, &new_instance) {
        eprintln!("Failed to save instance: {}", e);
        std::process::exit(1);
    }

    // Save the witness to file
    if let Err(e) = save_witness(witness_path, &new_witness) {
        eprintln!("Failed to save witness: {}", e);
        std::process::exit(1);
    }

    // Save the proof to file
    if let Err(e) = save_proof(proof_path, &res) {
        eprintln!("Failed to save proof: {}", e);
        std::process::exit(1);
    }
}

/// Prove a circuit and return results in memory (no file I/O).
/// This is the building block for the WASM `precompute()` API.
pub fn prove_circuit_in_memory<C: SpartanCircuit<E> + Clone + std::fmt::Debug>(
    circuit: C,
    pk: &<R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey,
) -> Result<
    (
        R1CSSNARK<E>,
        spartan2::r1cs::SplitR1CSInstance<E>,
        spartan2::r1cs::R1CSWitness<E>,
    ),
    SpartanError,
> {
    let mut prep_snark = R1CSSNARK::<E>::prep_prove(&pk, circuit.clone(), false)?;

    let mut transcript = <E as Engine>::TE::new(b"R1CSSNARK");
    transcript.absorb(b"vk", &pk.vk_digest);

    let public_values =
        SpartanCircuit::<E>::public_values(&circuit).map_err(|e| SpartanError::SynthesisError {
            reason: format!("Circuit does not provide public IO: {e}"),
        })?;

    transcript.absorb(b"public_values", &public_values.as_slice());

    let (instance, witness) = SatisfyingAssignment::r1cs_instance_and_witness(
        &mut prep_snark.ps,
        &pk.S,
        &pk.ck,
        &circuit,
        false,
        &mut transcript,
    )
    .map_err(|e| SpartanError::SynthesisError {
        reason: format!("Instance/witness generation failed: {e}"),
    })?;

    let proof = R1CSSNARK::<E>::prove_inner(&pk, &instance, &witness, &mut transcript)?;

    Ok((proof, instance, witness))
}

/// Reblind a proof with shared randomness and return results in memory (no file I/O).
/// This is the building block for the WASM `present()` API.
///
/// Uses the public values stored in the instance (from the original proving step)
/// rather than re-deriving them from the circuit. This is critical for WASM builds
/// where the circuit's `public_values()` may return zeros due to missing witness data.
pub fn reblind_in_memory(
    pk: &<R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey,
    instance: spartan2::r1cs::SplitR1CSInstance<E>,
    witness: spartan2::r1cs::R1CSWitness<E>,
    randomness: &[<E as Engine>::Scalar],
) -> Result<
    (
        R1CSSNARK<E>,
        spartan2::r1cs::SplitR1CSInstance<E>,
        spartan2::r1cs::R1CSWitness<E>,
    ),
    SpartanError,
> {
    assert_eq!(randomness.len(), instance.num_shared_rows());

    let mut reblind_transcript = <E as Engine>::TE::new(b"R1CSSNARK");
    reblind_transcript.absorb(b"vk", &pk.vk_digest);

    // Use the public values stored in the instance from the original proving step.
    // This ensures transcript consistency with the verifier, which also reads
    // public values from the proof's instance (not from a circuit).
    let public_values = instance.get_public_values();

    reblind_transcript.absorb(b"public_values", &public_values);

    let (new_instance, new_witness) = SatisfyingAssignment::reblind_r1cs_instance_and_witness(
        &randomness,
        instance,
        witness,
        &pk.ck,
        &mut reblind_transcript,
    )
    .map_err(|e| SpartanError::SynthesisError {
        reason: format!("Reblind failed: {e}"),
    })?;

    let proof =
        R1CSSNARK::<E>::prove_inner(&pk, &new_instance, &new_witness, &mut reblind_transcript)?;

    Ok((proof, new_instance, new_witness))
}

/// Only run the verification part using ZK-Spartan.
/// Returns the public values embedded in the proof.
#[cfg(not(target_arch = "wasm32"))]
pub fn verify_circuit(proof_path: impl AsRef<Path>, vk_path: impl AsRef<Path>) -> Vec<Scalar> {
    let proof = load_proof(&proof_path).expect("load proof failed");
    let vk = load_verifying_key(&vk_path).expect("load verifying key failed");

    verify_circuit_with_loaded_data(&proof, &vk)
}

/// Verify circuit with pre-loaded data - useful for benchmarking to exclude file I/O.
/// Returns the public values embedded in the proof.
#[cfg(not(target_arch = "wasm32"))]
pub fn verify_circuit_with_loaded_data(
    proof: &R1CSSNARK<E>,
    vk: &<R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey,
) -> Vec<Scalar> {
    let t0 = Instant::now();
    let public_values = proof.verify(&vk).expect("verify errored");
    let verify_ms = t0.elapsed().as_millis();
    info!(elapsed_ms = verify_ms, "ZK-Spartan verify");

    info!("Verification successful! Time: {} ms", verify_ms);
    public_values
}

/// Path-based single-proof verify that returns a bool instead of panicking
/// (Item 12): FFI/mobile callers must be able to report a false result rather
/// than crash across the boundary or return an unconditional `Ok(true)`.
#[cfg(not(target_arch = "wasm32"))]
pub fn try_verify_circuit(
    proof_path: impl AsRef<Path>,
    vk_path: impl AsRef<Path>,
) -> bool {
    let Ok(proof) = load_proof(&proof_path) else {
        return false;
    };
    let Ok(vk) = load_verifying_key(&vk_path) else {
        return false;
    };
    proof.verify(&vk).is_ok()
}

/// Path-based Prepare+Show linked verify for FFI/mobile: both proofs verify AND
/// share the same `comm_W_shared`. Returns a plain bool (never panics).
#[cfg(not(target_arch = "wasm32"))]
pub fn verify_linked_paths(
    prepare_proof_path: impl AsRef<Path>,
    prepare_vk_path: impl AsRef<Path>,
    show_proof_path: impl AsRef<Path>,
    show_vk_path: impl AsRef<Path>,
) -> bool {
    let (Ok(pp), Ok(pvk), Ok(sp), Ok(svk)) = (
        load_proof(&prepare_proof_path),
        load_verifying_key(&prepare_vk_path),
        load_proof(&show_proof_path),
        load_verifying_key(&show_vk_path),
    ) else {
        return false;
    };
    verify_linked(&pp, &pvk, &sp, &svk).is_some()
}

/// Verify a Prepare + Show proof pair AND their `comm_W_shared` linkage (Item 12).
///
/// Returns `Some((prepare_public_values, show_public_values))` only when BOTH
/// proofs verify and commit to the same shared witness; `None` otherwise.
/// Unlike `verify_circuit_with_loaded_data`, this never panics on an invalid
/// proof — it returns `None` — so FFI/mobile/CLI callers can report a real
/// result instead of `Ok(true)` (or a crash). The linkage is what stops an
/// honest Prepare being paired with an independently-forged Show over unrelated
/// claim values and a self-chosen device key.
#[cfg(not(target_arch = "wasm32"))]
pub fn verify_linked(
    prepare_proof: &R1CSSNARK<E>,
    prepare_vk: &<R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey,
    show_proof: &R1CSSNARK<E>,
    show_vk: &<R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey,
) -> Option<(Vec<Scalar>, Vec<Scalar>)> {
    let prepare_public_values = prepare_proof.verify(prepare_vk).ok()?;
    let show_public_values = show_proof.verify(show_vk).ok()?;

    // Both proofs must commit to the same shared witness. Read the commitments
    // from the verified proofs (not any caller-supplied instance).
    let prepare_shared = prepare_proof.comm_W_shared();
    let show_shared = show_proof.comm_W_shared();
    if prepare_shared.is_none() || show_shared.is_none() || prepare_shared != show_shared {
        return None;
    }
    Some((prepare_public_values, show_public_values))
}

/// Generate witness for the Prepare circuit (native builds only).
/// Returns the full witness vector.
///
/// # Arguments
/// * `config` - Path configuration for resolving file paths
/// * `input_json_path` - Optional override for input JSON path (absolute or relative to config.base_dir)
#[cfg(feature = "native-witness")]
pub fn generate_prepare_witness(
    config: &PathConfig,
    input_json_path: Option<&Path>,
) -> Result<Vec<Scalar>, SynthesisError> {
    let json_path = input_json_path
        .map(|p| config.resolve(p))
        .unwrap_or_else(|| config.input_json("jwt"));

    info!("Loading prepare inputs from {}", json_path.display());

    let json_file = File::open(&json_path).map_err(|_| SynthesisError::AssignmentMissing)?;

    let json_value: Value =
        serde_json::from_reader(json_file).map_err(|_| SynthesisError::AssignmentMissing)?;

    // Parse inputs using declarative field definitions
    let inputs = parse_jwt_inputs(&json_value)?;

    // Generate witness using witnesscalc
    info!("Generating witness using witnesscalc...");
    let t0 = Instant::now();

    let inputs_json = hashmap_to_json_string(
        &inputs,
        config.circuit_size.max_matches(),
        config.circuit_size.max_substring_length(),
        config.circuit_size.max_claims_length(),
    )?;

    // Generate raw witness bytes
    let witness_bytes = call_jwt_witness(config.circuit_size.circuit_name(), &inputs_json)?;

    info!("witnesscalc time: {} ms", t0.elapsed().as_millis());

    // Parse witness bytes directly to Scalar
    let witness = parse_witness(&witness_bytes)?;

    Ok(witness)
}

/// Stub for WASM builds - witness must be provided via with_witness() constructor.
#[cfg(not(feature = "native-witness"))]
pub fn generate_prepare_witness(
    _config: &PathConfig,
    _input_json_path: Option<&Path>,
) -> Result<Vec<Scalar>, SynthesisError> {
    Err(SynthesisError::AssignmentMissing)
}

/// Generate witness for the MDOC circuit (native builds only).
#[cfg(feature = "native-witness")]
pub fn generate_mdoc_witness(
    config: &PathConfig,
    input_json_path: Option<&Path>,
) -> Result<Vec<Scalar>, SynthesisError> {
    let json_path = input_json_path
        .map(|p| config.resolve(p))
        .unwrap_or_else(|| config.input_json("mdoc"));

    info!("Loading mdoc inputs from {}", json_path.display());

    let json_file = File::open(&json_path).map_err(|_| SynthesisError::AssignmentMissing)?;
    let json_value: Value =
        serde_json::from_reader(json_file).map_err(|_| SynthesisError::AssignmentMissing)?;

    let inputs = parse_mdoc_inputs(&json_value)?;

    info!("Generating mdoc witness using witnesscalc...");
    let t0 = Instant::now();

    let inputs_json = mdoc_hashmap_to_json_string(
        &inputs,
        MDOC_MAX_CLAIMS,
        MDOC_MAX_PREIMAGE_LEN,
        MDOC_MAX_IDENTIFIER_LEN,
        MDOC_MAX_VALUE_LEN,
    )?;

    let witness_bytes = call_mdoc_witness(&inputs_json)?;

    info!("mdoc witnesscalc time: {} ms", t0.elapsed().as_millis());

    parse_witness(&witness_bytes)
}

#[cfg(not(feature = "native-witness"))]
pub fn generate_mdoc_witness(
    _config: &PathConfig,
    _input_json_path: Option<&Path>,
) -> Result<Vec<Scalar>, SynthesisError> {
    Err(SynthesisError::AssignmentMissing)
}

/// Generate witness for the JSON-LD circuit (native builds only).
#[cfg(feature = "native-witness")]
pub fn generate_jsonld_witness(
    config: &PathConfig,
    input_json_path: Option<&Path>,
) -> Result<Vec<Scalar>, SynthesisError> {
    let json_path = input_json_path
        .map(|p| config.resolve(p))
        .unwrap_or_else(|| config.input_json("jsonld"));

    info!("Loading jsonld inputs from {}", json_path.display());

    let json_file = File::open(&json_path).map_err(|_| SynthesisError::AssignmentMissing)?;
    let json_value: Value =
        serde_json::from_reader(json_file).map_err(|_| SynthesisError::AssignmentMissing)?;

    let inputs = parse_jsonld_inputs(&json_value)?;

    info!("Generating jsonld witness using witnesscalc...");
    let t0 = Instant::now();

    let inputs_json = serde_json::to_string(&inputs).map_err(|_| SynthesisError::Unsatisfiable)?;
    let witness_bytes = call_jsonld_witness(&inputs_json)?;

    info!("jsonld witnesscalc time: {} ms", t0.elapsed().as_millis());

    parse_witness(&witness_bytes)
}

#[cfg(not(feature = "native-witness"))]
pub fn generate_jsonld_witness(
    _config: &PathConfig,
    _input_json_path: Option<&Path>,
) -> Result<Vec<Scalar>, SynthesisError> {
    Err(SynthesisError::AssignmentMissing)
}

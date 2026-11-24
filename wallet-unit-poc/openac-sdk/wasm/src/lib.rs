use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use ecdsa_spartan2::{
    circuit_size::CircuitSize, parse_witness, prove_circuit_in_memory, reblind_in_memory,
    PrepareCircuit, ShowCircuit,
};
use ecdsa_spartan2::{Scalar, E};

use spartan2::{traits::snark::R1CSSNARKTrait, zk_spartan::R1CSSNARK};

use ff::Field;

// ==========================================================================
// Result types for JS interop
// ==========================================================================

/// Combined setup result for both circuits
#[derive(Serialize, Deserialize)]
pub struct SetupResult {
    pub prepare_pk: Vec<u8>,
    pub prepare_vk: Vec<u8>,
    pub show_pk: Vec<u8>,
    pub show_vk: Vec<u8>,
}

/// Individual circuit setup result (for backward compatibility)
#[derive(Serialize, Deserialize)]
pub struct SingleSetupResult {
    pub pk: Vec<u8>,
    pub vk: Vec<u8>,
}

/// Result from precompute (proving the Prepare circuit)
#[derive(Serialize, Deserialize)]
pub struct PrecomputeResult {
    pub proof: Vec<u8>,
    pub instance: Vec<u8>,
    pub witness: Vec<u8>,
}

/// Result from present (reblind Prepare + prove Show + reblind Show)
#[derive(Serialize, Deserialize)]
pub struct PresentResult {
    pub prepare_proof: Vec<u8>,
    pub prepare_instance: Vec<u8>,
    pub show_proof: Vec<u8>,
    pub show_instance: Vec<u8>,
}

/// Combined verification result
///
/// Prepare's public values are returned so the caller can bind the presentation
/// to an issuer it trusts: they are `[pubKeyX, pubKeyY, decodeFlags[n],
/// claimFormats[n]]`. Normalized claim values and the device key were removed
/// from this vector (they now reach Show privately via `comm_W_shared`), so
/// returning it no longer leaks the holder's attributes or a stable identifier.
/// Dropping it entirely would leave `valid` meaning "signed by some P-256 key".
#[derive(Serialize, Deserialize)]
pub struct VerifyResult {
    pub valid: bool,
    pub prepare_public_values: Vec<String>,
    pub show_public_values: Vec<String>,
    pub error: Option<String>,
}

// Same encoding as `bincode::serialize` (fixint, little-endian), plus a byte
// limit and no trailing bytes, so each value has exactly one accepted byte
// string. bincode ignores `with_limit` when deserializing from a slice, so the
// bytes go through a reader, where a length prefix larger than the limit fails
// before any buffer is allocated for it. Readers also skip bincode's own
// trailing-bytes check, hence the explicit one.
fn decode_limited<T: serde::de::DeserializeOwned>(bytes: &[u8], limit: u64) -> bincode::Result<T> {
    use bincode::Options;
    let mut reader = bytes;
    let value = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(limit)
        .deserialize_from(&mut reader)?;
    if !reader.is_empty() {
        return Err(Box::new(bincode::ErrorKind::Custom(format!(
            "{} trailing bytes after value",
            reader.len()
        ))));
    }
    Ok(value)
}

/// Nothing legitimately decodes to more bytes than it was encoded from.
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> bincode::Result<T> {
    decode_limited(bytes, bytes.len() as u64)
}

/// Upper bound for caller-supplied proofs and instances. Honest ones are far
/// smaller; this stops an oversized input from being accepted at all.
const MAX_UNTRUSTED_BYTES: usize = 64 * 1024 * 1024;

fn decode_untrusted<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> bincode::Result<T> {
    if bytes.len() > MAX_UNTRUSTED_BYTES {
        return Err(Box::new(bincode::ErrorKind::SizeLimit));
    }
    decode(bytes)
}

#[cfg(test)]
mod decode_tests {
    use super::*;

    #[test]
    fn round_trips_with_default_serialize() {
        let v: Vec<u8> = vec![1, 2, 3, 4];
        let bytes = bincode::serialize(&v).unwrap();
        assert_eq!(decode::<Vec<u8>>(&bytes).unwrap(), v);
    }

    #[test]
    fn trailing_byte_is_an_error() {
        let mut bytes = bincode::serialize(&vec![1u8, 2, 3, 4]).unwrap();
        bytes.push(0);
        assert!(decode::<Vec<u8>>(&bytes).is_err());
        assert!(decode_untrusted::<Vec<u8>>(&bytes).is_err());
    }

    #[test]
    fn byte_limit_is_enforced() {
        // Well-formed and complete, so only the limit can make these fail.
        let text = bincode::serialize(&"x".repeat(100)).unwrap();
        assert!(decode_limited::<String>(&text, text.len() as u64).is_ok());
        assert!(decode_limited::<String>(&text, 10).is_err());

        let nums = bincode::serialize(&vec![7u64; 20]).unwrap();
        assert!(decode_limited::<Vec<u64>>(&nums, nums.len() as u64).is_ok());
        assert!(decode_limited::<Vec<u64>>(&nums, 10).is_err());
    }

    #[test]
    fn input_over_the_untrusted_cap_is_rejected() {
        let bytes = vec![0u8; MAX_UNTRUSTED_BYTES + 1];
        assert!(decode_untrusted::<Vec<u8>>(&bytes).is_err());
    }
}

/// Initialize panic hook for better error messages in WASM
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Contract version checked by the SDK at load time. Keep in step with
/// `ABI_VERSION` in src/wasm-bridge.ts.
#[wasm_bindgen]
pub fn abi_version() -> u32 {
    1
}

// ==========================================================================
// 1. SETUP — Generate keys for both circuits (one-time)
// ==========================================================================

/// Setup both Prepare and Show circuit keys in a single call.
/// Returns serialized SetupResult with proving and verifying keys for both circuits.
#[wasm_bindgen]
pub fn setup() -> Result<JsValue, JsError> {
    // Setup Prepare circuit
    let prepare_circuit = PrepareCircuit::default();
    let (prepare_pk, prepare_vk) = R1CSSNARK::<E>::setup(prepare_circuit)
        .map_err(|e| JsError::new(&format!("Prepare setup failed: {:?}", e)))?;

    // Setup Show circuit
    let show_circuit = ShowCircuit::default();
    let (show_pk, show_vk) = R1CSSNARK::<E>::setup(show_circuit)
        .map_err(|e| JsError::new(&format!("Show setup failed: {:?}", e)))?;

    // Serialize all keys
    let result = SetupResult {
        prepare_pk: bincode::serialize(&prepare_pk)
            .map_err(|e| JsError::new(&format!("Prepare PK serialization failed: {}", e)))?,
        prepare_vk: bincode::serialize(&prepare_vk)
            .map_err(|e| JsError::new(&format!("Prepare VK serialization failed: {}", e)))?,
        show_pk: bincode::serialize(&show_pk)
            .map_err(|e| JsError::new(&format!("Show PK serialization failed: {}", e)))?,
        show_vk: bincode::serialize(&show_vk)
            .map_err(|e| JsError::new(&format!("Show VK serialization failed: {}", e)))?,
    };

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)))
}

// ==========================================================================
// 2. PRECOMPUTE — Prove Prepare circuit (once per credential)
// ==========================================================================

/// Prove the Prepare circuit and return proof/instance/witness for storage.
/// This is called once when a credential is added to the wallet.
/// The results should be stored and reused for each presentation via `present()`.
///
/// Arguments:
/// - `pk_bytes`: Serialized Prepare proving key (from setup())
///
/// Returns: PrecomputeResult { proof, instance, witness } — all as serialized bytes
#[wasm_bindgen]
pub fn precompute(pk_bytes: &[u8]) -> Result<JsValue, JsError> {
    // Deserialize the proving key
    let pk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey = decode(pk_bytes)
        .map_err(|e| JsError::new(&format!("PK deserialization failed: {}", e)))?;

    // Create the Prepare circuit
    let circuit = PrepareCircuit::default();

    // Prove in memory (no file I/O)
    let (proof, instance, witness) = prove_circuit_in_memory(circuit, &pk)
        .map_err(|e| JsError::new(&format!("Prepare proving failed: {:?}", e)))?;

    // Serialize results
    let result = PrecomputeResult {
        proof: bincode::serialize(&proof)
            .map_err(|e| JsError::new(&format!("Proof serialization failed: {}", e)))?,
        instance: bincode::serialize(&instance)
            .map_err(|e| JsError::new(&format!("Instance serialization failed: {}", e)))?,
        witness: bincode::serialize(&witness)
            .map_err(|e| JsError::new(&format!("Witness serialization failed: {}", e)))?,
    };

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)))
}

// ==========================================================================
// 2b. PRECOMPUTE FROM WITNESS — Prove circuit with externally generated witness
// ==========================================================================

/// Prove the Prepare circuit using externally generated witness bytes.
/// This is used when witness is generated by TypeScript WitnessCalculator.
///
/// Arguments:
/// - `pk_bytes`: Serialized Prepare proving key (from setup())
/// - `witness_wtns_bytes`: Circom WTNS binary witness (from TypeScript WitnessCalculator)
///
/// Returns: PrecomputeResult { proof, instance, witness } — all as serialized bytes
#[wasm_bindgen]
pub fn precompute_from_witness(
    pk_bytes: &[u8],
    witness_wtns_bytes: &[u8],
    vc_size: &str,
) -> Result<JsValue, JsError> {
    // The size picks the per-size witness offset of `normalizedClaimValues`;
    // getting it wrong makes the shared commitment disagree with Show.
    let circuit_size: CircuitSize = vc_size
        .parse()
        .map_err(|e: String| JsError::new(&format!("Invalid vc_size: {e}")))?;

    // Deserialize the proving key
    let pk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey = decode(pk_bytes)
        .map_err(|e| JsError::new(&format!("PK deserialization failed: {}", e)))?;

    // Parse WTNS bytes to Vec<Scalar>
    let witness_scalars = parse_witness(witness_wtns_bytes)
        .map_err(|e| JsError::new(&format!("Witness parsing failed: {:?}", e)))?;

    // Create circuit with pre-computed witness (bypasses filesystem I/O)
    let circuit = PrepareCircuit::with_witness_for_size(witness_scalars, circuit_size);

    // Prove in memory
    let (proof, instance, witness) = prove_circuit_in_memory(circuit, &pk)
        .map_err(|e| JsError::new(&format!("Prepare proving failed: {:?}", e)))?;

    // Serialize results
    let result = PrecomputeResult {
        proof: bincode::serialize(&proof)
            .map_err(|e| JsError::new(&format!("Proof serialization failed: {}", e)))?,
        instance: bincode::serialize(&instance)
            .map_err(|e| JsError::new(&format!("Instance serialization failed: {}", e)))?,
        witness: bincode::serialize(&witness)
            .map_err(|e| JsError::new(&format!("Witness serialization failed: {}", e)))?,
    };

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)))
}

/// Prove the Show circuit using externally generated witness bytes.
/// This is used when witness is generated by TypeScript WitnessCalculator.
///
/// Arguments:
/// - `pk_bytes`: Serialized Show proving key (from setup())
/// - `witness_wtns_bytes`: Circom WTNS binary witness (from TypeScript WitnessCalculator)
///
/// Returns: PrecomputeResult { proof, instance, witness } — all as serialized bytes
#[wasm_bindgen]
pub fn precompute_show_from_witness(
    pk_bytes: &[u8],
    witness_wtns_bytes: &[u8],
) -> Result<JsValue, JsError> {
    // Deserialize the proving key
    let pk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey = decode(pk_bytes)
        .map_err(|e| JsError::new(&format!("PK deserialization failed: {}", e)))?;

    // Parse WTNS bytes to Vec<Scalar>
    let witness_scalars = parse_witness(witness_wtns_bytes)
        .map_err(|e| JsError::new(&format!("Witness parsing failed: {:?}", e)))?;

    // Create circuit with pre-computed witness (bypasses filesystem I/O)
    let circuit = ShowCircuit::with_witness(witness_scalars);

    // Prove in memory
    let (proof, instance, witness) = prove_circuit_in_memory(circuit, &pk)
        .map_err(|e| JsError::new(&format!("Show proving failed: {:?}", e)))?;

    // Serialize results
    let result = PrecomputeResult {
        proof: bincode::serialize(&proof)
            .map_err(|e| JsError::new(&format!("Proof serialization failed: {}", e)))?,
        instance: bincode::serialize(&instance)
            .map_err(|e| JsError::new(&format!("Instance serialization failed: {}", e)))?,
        witness: bincode::serialize(&witness)
            .map_err(|e| JsError::new(&format!("Witness serialization failed: {}", e)))?,
    };

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)))
}

// ==========================================================================
// 3. PRESENT — Reblind both pre-proved circuits with shared randomness
// ==========================================================================

/// Execute a full presentation: generate shared blinds and reblind both the
/// Prepare and Show proofs using the same randomness.
///
/// This is called each time the holder presents to a verifier. Both circuits
/// must already be proved (via the TypeScript WitnessCalculator + prove path).
/// This function generates fresh shared blinds and reblinds both proofs to
/// ensure unlinkability while maintaining cryptographic linkage (comm_W_shared).
///
/// Arguments:
/// - `prepare_pk_bytes`:       Serialized Prepare proving key
/// - `prepare_instance_bytes`: Serialized Prepare instance (from prove step)
/// - `prepare_witness_bytes`:  Serialized Prepare witness (from prove step)
/// - `show_pk_bytes`:          Serialized Show proving key
/// - `show_instance_bytes`:    Serialized Show instance (from prove step)
/// - `show_witness_bytes`:     Serialized Show witness (from prove step)
///
/// Returns: PresentResult { prepare_proof, prepare_instance, show_proof, show_instance }
#[wasm_bindgen]
pub fn present(
    prepare_pk_bytes: &[u8],
    prepare_instance_bytes: &[u8],
    prepare_witness_bytes: &[u8],
    show_pk_bytes: &[u8],
    show_instance_bytes: &[u8],
    show_witness_bytes: &[u8],
) -> Result<JsValue, JsError> {
    // Deserialize Prepare components
    let prepare_pk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey =
        decode(prepare_pk_bytes)
            .map_err(|e| JsError::new(&format!("Prepare PK deserialization failed: {}", e)))?;
    let prepare_instance: spartan2::r1cs::SplitR1CSInstance<E> =
        decode_untrusted(prepare_instance_bytes).map_err(|e| {
            JsError::new(&format!("Prepare instance deserialization failed: {}", e))
        })?;
    let prepare_witness: spartan2::r1cs::R1CSWitness<E> =
        decode(prepare_witness_bytes)
            .map_err(|e| JsError::new(&format!("Prepare witness deserialization failed: {}", e)))?;

    // Deserialize Show components
    let show_pk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey =
        decode(show_pk_bytes)
            .map_err(|e| JsError::new(&format!("Show PK deserialization failed: {}", e)))?;
    let show_instance: spartan2::r1cs::SplitR1CSInstance<E> =
        decode_untrusted(show_instance_bytes)
            .map_err(|e| JsError::new(&format!("Show instance deserialization failed: {}", e)))?;
    let show_witness: spartan2::r1cs::R1CSWitness<E> = decode(show_witness_bytes)
        .map_err(|e| JsError::new(&format!("Show witness deserialization failed: {}", e)))?;

    // Step A: Generate shared blinds
    let num_shared = prepare_instance.num_shared_rows();
    let shared_blinds: Vec<Scalar> = (0..num_shared)
        .map(|_| Scalar::random(&mut rand::thread_rng()))
        .collect();

    // Step B: Reblind Prepare proof with shared blinds
    // Public values are read from the instance (set during original proving).
    let (reblinded_prepare_proof, reblinded_prepare_instance, _reblinded_prepare_witness) =
        reblind_in_memory(
            &prepare_pk,
            prepare_instance,
            prepare_witness,
            &shared_blinds,
        )
        .map_err(|e| JsError::new(&format!("Prepare reblind failed: {:?}", e)))?;

    // Step C: Reblind Show proof with the same shared blinds
    let (reblinded_show_proof, reblinded_show_instance, _reblinded_show_witness) =
        reblind_in_memory(&show_pk, show_instance, show_witness, &shared_blinds)
            .map_err(|e| JsError::new(&format!("Show reblind failed: {:?}", e)))?;

    // Serialize results (blinds are NOT returned — they're ephemeral)
    let result = PresentResult {
        prepare_proof: bincode::serialize(&reblinded_prepare_proof)
            .map_err(|e| JsError::new(&format!("Prepare proof serialization failed: {}", e)))?,
        prepare_instance: bincode::serialize(&reblinded_prepare_instance)
            .map_err(|e| JsError::new(&format!("Prepare instance serialization failed: {}", e)))?,
        show_proof: bincode::serialize(&reblinded_show_proof)
            .map_err(|e| JsError::new(&format!("Show proof serialization failed: {}", e)))?,
        show_instance: bincode::serialize(&reblinded_show_instance)
            .map_err(|e| JsError::new(&format!("Show instance serialization failed: {}", e)))?,
    };

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)))
}

// ==========================================================================
// 4. VERIFY — Verify both proofs + commitment check (per presentation)
// ==========================================================================

/// Complete verification: verify both Prepare and Show proofs and compare their
/// shared commitments (comm_W_shared) to ensure they use the same private data.
///
/// Arguments:
/// - `prepare_proof_bytes`:    Serialized Prepare proof (from present())
/// - `prepare_vk_bytes`:       Serialized Prepare verifying key (from setup())
/// - `prepare_instance_bytes`: Serialized Prepare instance (from present())
/// - `show_proof_bytes`:       Serialized Show proof (from present())
/// - `show_vk_bytes`:          Serialized Show verifying key (from setup())
/// - `show_instance_bytes`:    Serialized Show instance (from present())
///
/// Returns: VerifyResult { valid, prepare_public_values, show_public_values, error? }
#[wasm_bindgen]
pub fn verify(
    prepare_proof_bytes: &[u8],
    prepare_vk_bytes: &[u8],
    prepare_instance_bytes: &[u8],
    show_proof_bytes: &[u8],
    show_vk_bytes: &[u8],
    show_instance_bytes: &[u8],
) -> Result<JsValue, JsError> {
    // Deserialize all components
    let prepare_proof: R1CSSNARK<E> = decode_untrusted(prepare_proof_bytes)
        .map_err(|e| JsError::new(&format!("Prepare proof deserialization failed: {}", e)))?;
    let prepare_vk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey =
        decode(prepare_vk_bytes)
            .map_err(|e| JsError::new(&format!("Prepare VK deserialization failed: {}", e)))?;
    // Instances are deserialized for input-shape compatibility only. They are
    // caller-supplied and unauthenticated, so linkage must not depend on them;
    // the commitment comparison below reads from the verified proofs instead.
    let _prepare_instance: spartan2::r1cs::SplitR1CSInstance<E> =
        decode_untrusted(prepare_instance_bytes).map_err(|e| {
            JsError::new(&format!("Prepare instance deserialization failed: {}", e))
        })?;

    let show_proof: R1CSSNARK<E> = decode_untrusted(show_proof_bytes)
        .map_err(|e| JsError::new(&format!("Show proof deserialization failed: {}", e)))?;
    let show_vk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey =
        decode(show_vk_bytes)
            .map_err(|e| JsError::new(&format!("Show VK deserialization failed: {}", e)))?;
    let _show_instance: spartan2::r1cs::SplitR1CSInstance<E> =
        decode_untrusted(show_instance_bytes)
            .map_err(|e| JsError::new(&format!("Show instance deserialization failed: {}", e)))?;

    // Prepare's public IO carries the issuer key the credential was verified
    // against; the caller needs it to decide whether to trust the issuer.
    let prepare_pv = match prepare_proof.verify(&prepare_vk) {
        Ok(pv) => pv,
        Err(e) => {
            let result = VerifyResult {
                valid: false,
                prepare_public_values: vec![],
                show_public_values: vec![],
                error: Some(format!("Prepare proof verification failed: {:?}", e)),
            };
            return serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)));
        }
    };

    let show_pv = match show_proof.verify(&show_vk) {
        Ok(pv) => pv,
        Err(e) => {
            let result = VerifyResult {
                valid: false,
                prepare_public_values: vec![],
                show_public_values: vec![],
                error: Some(format!("Show proof verification failed: {:?}", e)),
            };
            return serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)));
        }
    };

    // Linkage: both proofs must commit to the same shared witness. Read the
    // commitments from the verified proofs, not the caller-supplied instances.
    let prepare_shared = prepare_proof.comm_W_shared();
    let show_shared = show_proof.comm_W_shared();
    let commitment_valid = prepare_shared.is_some()
        && show_shared.is_some()
        && prepare_shared == show_shared;
    if !commitment_valid {
        let result = VerifyResult {
            valid: false,
            prepare_public_values: vec![],
            show_public_values: vec![],
            error: Some("Shared commitment mismatch: prepare and show proofs do not share the same private data".to_string()),
        };
        return serde_wasm_bindgen::to_value(&result)
            .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)));
    }

    // All checks passed
    let result = VerifyResult {
        valid: true,
        prepare_public_values: prepare_pv.iter().map(|s| format!("{:?}", s)).collect(),
        show_public_values: show_pv.iter().map(|s| format!("{:?}", s)).collect(),
        error: None,
    };
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)))
}

// ==========================================================================
// Backward-compatible individual functions (deprecated — use above instead)
// ==========================================================================

/// Setup Prepare circuit keys only (use setup() instead)
#[wasm_bindgen]
pub fn setup_prepare() -> Result<JsValue, JsError> {
    let circuit = PrepareCircuit::default();
    let (pk, vk) = R1CSSNARK::<E>::setup(circuit)
        .map_err(|e| JsError::new(&format!("Setup failed: {:?}", e)))?;

    let result = SingleSetupResult {
        pk: bincode::serialize(&pk)
            .map_err(|e| JsError::new(&format!("PK serialization failed: {}", e)))?,
        vk: bincode::serialize(&vk)
            .map_err(|e| JsError::new(&format!("VK serialization failed: {}", e)))?,
    };
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)))
}

/// Setup Show circuit keys only (use setup() instead)
#[wasm_bindgen]
pub fn setup_show() -> Result<JsValue, JsError> {
    let circuit = ShowCircuit::default();
    let (pk, vk) = R1CSSNARK::<E>::setup(circuit)
        .map_err(|e| JsError::new(&format!("Setup failed: {:?}", e)))?;

    let result = SingleSetupResult {
        pk: bincode::serialize(&pk)
            .map_err(|e| JsError::new(&format!("PK serialization failed: {}", e)))?,
        vk: bincode::serialize(&vk)
            .map_err(|e| JsError::new(&format!("VK serialization failed: {}", e)))?,
    };
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)))
}

/// Verify a single proof (use verify() instead)
#[wasm_bindgen]
pub fn verify_single(proof_bytes: &[u8], vk_bytes: &[u8]) -> Result<JsValue, JsError> {
    let proof: R1CSSNARK<E> = decode(proof_bytes)
        .map_err(|e| JsError::new(&format!("Proof deserialization failed: {}", e)))?;
    let vk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey = decode(vk_bytes)
        .map_err(|e| JsError::new(&format!("VK deserialization failed: {}", e)))?;

    match proof.verify(&vk) {
        Ok(public_values) => {
            let pv_strings: Vec<String> =
                public_values.iter().map(|s| format!("{:?}", s)).collect();
            let result = serde_json::json!({
                "valid": true,
                "public_values": pv_strings,
            });
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)))
        }
        Err(_e) => {
            let result = serde_json::json!({
                "valid": false,
                "public_values": Vec::<String>::new(),
            });
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsError::new(&format!("JS conversion failed: {}", e)))
        }
    }
}

// Item 18: `compare_comm_w_shared` removed. It compared comm_W_shared read from
// CALLER-supplied, unauthenticated instance blobs — exactly the input the
// hardened `verify()` refuses to trust — so a caller composing it to emulate a
// linkage check could be handed two matching blobs by an attacker. The real
// linkage check inside `verify()` reads the commitments from the verified
// proofs. Use `verify()`.

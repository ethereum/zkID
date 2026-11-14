//! Standalone WebAssembly crate for Spartan2 zkID proving.
//! Supports all zkID circuits via runtime `CircuitKind`.
//! Transcript flow is kept in sync with `ecdsa-spartan2` by `native_drift`.

pub mod inputs;

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use serde::{Deserialize, Serialize};
use spartan2::{
    bellpepper::{solver::SatisfyingAssignment, zk_r1cs::SpartanWitness},
    provider::T256HyraxEngine,
    traits::{
        circuit::SpartanCircuit, snark::R1CSSNARKTrait, transcript::TranscriptEngineTrait, Engine,
    },
    zk_spartan::R1CSSNARK,
};
use std::collections::VecDeque;
use std::io::Read;
use std::sync::Mutex;
use wasm_bindgen::prelude::*;

pub use wasm_bindgen_rayon::init_thread_pool;

// ── Type aliases (from ecdsa-spartan2/src/lib.rs) ────────────────────────────
pub type E = T256HyraxEngine;
pub type Scalar = <E as Engine>::Scalar;

// Public aliases so the native drift test can round-trip proofs via bincode
// with the same concrete types ecdsa-spartan2 uses.
pub type R1CSSNARKForTest = R1CSSNARK<E>;
pub type VerifierKeyForTest = <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey;

// ── CircuitKind and its metadata ─────────────────────────────────────────────
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CircuitKind {
    CertChainRs2048 = 0,
    CertChainRs4096 = 1,
    UserSigRs2048 = 2,
}

impl CircuitKind {
    /// NUM_PUBLIC per circuit.
    pub fn num_public(self) -> usize {
        match self {
            CircuitKind::CertChainRs2048 => 20,
            CircuitKind::CertChainRs4096 => 37,
            // pk_commit, nullifier, app_id_packed, challenge.
            CircuitKind::UserSigRs2048 => 4,
        }
    }

    /// Index into `public_values` for `pk_commit`.
    pub fn pk_commit_index(self) -> usize {
        match self {
            CircuitKind::CertChainRs2048
            | CircuitKind::CertChainRs4096
            | CircuitKind::UserSigRs2048 => 0,
        }
    }
}

// Parse circom `.wtns` into scalars with checked offset arithmetic.
fn parse_witness(witness_bytes: &[u8]) -> Result<Vec<Scalar>, SynthesisError> {
    let len = witness_bytes.len();
    let mut pos = 0usize;
    if len < 12 || &witness_bytes[0..4] != b"wtns" {
        return Err(SynthesisError::Unsatisfiable);
    }
    pos += 8; // magic + version (fixed small literal, no overflow risk)
    if len.saturating_sub(pos) < 4 {
        return Err(SynthesisError::Unsatisfiable);
    }
    let n_sections = u32::from_le_bytes(witness_bytes[pos..pos + 4].try_into().unwrap());
    pos += 4;
    let mut n8 = 0usize;
    for _ in 0..n_sections {
        if len.saturating_sub(pos) < 12 {
            return Err(SynthesisError::Unsatisfiable);
        }
        let section_id = u32::from_le_bytes(witness_bytes[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let section_length =
            u64::from_le_bytes(witness_bytes[pos..pos + 8].try_into().unwrap()) as usize;
        pos += 8;
        match section_id {
            1 => {
                if len.saturating_sub(pos) < 4 {
                    return Err(SynthesisError::Unsatisfiable);
                }
                n8 = u32::from_le_bytes(witness_bytes[pos..pos + 4].try_into().unwrap()) as usize;
                // Advance to the next section safely.
                pos = pos.saturating_add(section_length);
            }
            2 => {
                let end = pos
                    .checked_add(section_length)
                    .ok_or(SynthesisError::Unsatisfiable)?;
                if n8 == 0 || end > len {
                    return Err(SynthesisError::Unsatisfiable);
                }
                let data = &witness_bytes[pos..end];
                let num = section_length / n8;
                let mut scalars = Vec::with_capacity(num);
                for chunk in data.chunks(n8) {
                    let mut padded = [0u8; 32];
                    padded[..chunk.len()].copy_from_slice(chunk);
                    let s = Scalar::from_bytes(&padded)
                        .into_option()
                        .ok_or(SynthesisError::Unsatisfiable)?;
                    scalars.push(s);
                }
                return Ok(scalars);
            }
            _ => pos = pos.saturating_add(section_length),
        }
    }
    Err(SynthesisError::Unsatisfiable)
}

// ── WasmCircuit: parameterized by NUM_PUBLIC ─────────────────────────────────
#[derive(Clone, Debug)]
struct WasmCircuit {
    witness: Vec<Scalar>,
    num_public: usize,
}

impl SpartanCircuit<E> for WasmCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self, cs: &mut CS, _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>], _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let num_inputs = 1 + self.num_public;
        if self.witness.len() < num_inputs { return Err(SynthesisError::Unsatisfiable); }
        let num_aux = self.witness.len() - num_inputs;
        for i in 1..num_inputs {
            AllocatedNum::alloc_input(cs.namespace(|| format!("public_{}", i)),
                || Ok(self.witness[i]))?;
        }
        for i in 0..num_aux {
            AllocatedNum::alloc(cs.namespace(|| format!("aux_{}", i)),
                || Ok(self.witness[i + num_inputs]))?;
        }
        Ok(())
    }
    fn shared<CS: ConstraintSystem<Scalar>>(&self, _: &mut CS)
        -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> { Ok(vec![]) }
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        if self.witness.len() < 1 + self.num_public { return Err(SynthesisError::Unsatisfiable); }
        Ok(self.witness[1..=self.num_public].to_vec())
    }
    fn precommitted<CS: ConstraintSystem<Scalar>>(&self, _: &mut CS,
        _: &[AllocatedNum<Scalar>]) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }
    fn num_challenges(&self) -> usize { 0 }
}

// ── Global PK cache: one slot per CircuitKind ────────────────────────────────
type PkCell = Mutex<Option<<R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey>>;
static PK_CERT_2048: PkCell = Mutex::new(None);
static PK_CERT_4096: PkCell = Mutex::new(None);
static PK_USER_SIG_2048: PkCell = Mutex::new(None);

fn pk_slot(kind: CircuitKind) -> &'static PkCell {
    match kind {
        CircuitKind::CertChainRs2048 => &PK_CERT_2048,
        CircuitKind::CertChainRs4096 => &PK_CERT_4096,
        CircuitKind::UserSigRs2048 => &PK_USER_SIG_2048,
    }
}

/// Lock PK slot and recover from poison to avoid wasm runtime abort.
fn lock_pk_mut(
    kind: CircuitKind,
) -> std::sync::MutexGuard<'static, Option<<R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey>> {
    pk_slot(kind).lock().unwrap_or_else(|e| e.into_inner())
}

// ── Streaming PK load: one in-flight buffer per CircuitKind ──────────────────
enum PendingBuf {
    Eager { buf: Vec<u8>, total_size: usize },
    Streaming {
        chunks: VecDeque<Vec<u8>>,
        total_size: usize,
        len: usize,
    },
}

type PendingCell = Mutex<Option<PendingBuf>>;
static PENDING_CERT_2048: PendingCell = Mutex::new(None);
static PENDING_CERT_4096: PendingCell = Mutex::new(None);
static PENDING_USER_SIG_2048: PendingCell = Mutex::new(None);

fn pending_slot(kind: CircuitKind) -> &'static PendingCell {
    match kind {
        CircuitKind::CertChainRs2048 => &PENDING_CERT_2048,
        CircuitKind::CertChainRs4096 => &PENDING_CERT_4096,
        CircuitKind::UserSigRs2048 => &PENDING_USER_SIG_2048,
    }
}

fn lock_pending(kind: CircuitKind) -> std::sync::MutexGuard<'static, Option<PendingBuf>> {
    pending_slot(kind).lock().unwrap_or_else(|e| e.into_inner())
}

// Pops each Vec<u8> once fully consumed so the wasm allocator can reuse
// that capacity for ProverKey allocations still in flight.
struct ChunkDrainReader {
    chunks: VecDeque<Vec<u8>>,
    front_off: usize,
}

impl Read for ChunkDrainReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut written = 0;
        while written < buf.len() {
            let Some(front) = self.chunks.front() else { break };
            let avail = &front[self.front_off..];
            // Both pops are load-bearing: top releases a zero-length front,
            // bottom releases the moment the current front is exhausted so
            // the allocator sees the freed capacity before the next read.
            if avail.is_empty() {
                self.chunks.pop_front();
                self.front_off = 0;
                continue;
            }
            let n = avail.len().min(buf.len() - written);
            buf[written..written + n].copy_from_slice(&avail[..n]);
            self.front_off += n;
            written += n;
            if self.front_off >= front.len() {
                self.chunks.pop_front();
                self.front_off = 0;
            }
        }
        Ok(written)
    }
}

// Core prove path shared by wasm_bindgen and native test entry points.
// Keep transcript order aligned with `ecdsa-spartan2` and `native_drift`.
fn prove_core(
    pk: &<R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey,
    kind: CircuitKind,
    wtns_bytes: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<Scalar>), String> {
    let witness = parse_witness(wtns_bytes).map_err(|e| format!("witness parse: {e:?}"))?;
    let circuit = WasmCircuit { witness, num_public: kind.num_public() };

    let mut prep_snark = R1CSSNARK::<E>::prep_prove(pk, circuit.clone(), false)
        .map_err(|e| format!("prep_prove: {e:?}"))?;
    let mut t = <E as Engine>::TE::new(b"R1CSSNARK");
    t.absorb(b"vk", &pk.vk_digest);
    let public_values = SpartanCircuit::<E>::public_values(&circuit)
        .map_err(|e| format!("public_values: {e:?}"))?;
    t.absorb(b"public_values", &public_values.as_slice());
    let (instance, witness) = SatisfyingAssignment::r1cs_instance_and_witness(
        &mut prep_snark.ps, &pk.S, &pk.ck, &circuit, false, &mut t,
    ).map_err(|e| format!("instance/witness: {e:?}"))?;
    let proof = R1CSSNARK::<E>::prove_inner(pk, &instance, &witness, &mut t)
        .map_err(|e| format!("prove_inner: {e:?}"))?;

    Ok((
        bincode::serialize(&proof).map_err(|e| e.to_string())?,
        bincode::serialize(&instance).map_err(|e| e.to_string())?,
        public_values,
    ))
}

// ── wasm-bindgen entry points ────────────────────────────────────────────────
#[wasm_bindgen(start)]
pub fn wasm_init() { console_error_panic_hook::set_once(); }

#[wasm_bindgen]
pub fn load_pk(kind: CircuitKind, pk_bytes: &[u8]) -> Result<(), JsError> {
    let pk = bincode::deserialize(pk_bytes)
        .map_err(|e| JsError::new(&format!("PK deserialize ({kind:?}): {e}")))?;
    *lock_pk_mut(kind) = Some(pk);
    Ok(())
}

// Native-callable cores for the streaming PK load. The `#[wasm_bindgen]`
// entry points below wrap these with `String -> JsError`. Mirrors
// `prove_core` so unit tests can target the cores directly.
fn load_pk_begin_core(
    kind: CircuitKind,
    total_size: usize,
    low_memory_mode: bool,
) -> Result<(), String> {
    let pending = if low_memory_mode {
        PendingBuf::Streaming {
            chunks: VecDeque::new(),
            total_size,
            len: 0,
        }
    } else {
        let mut buf = Vec::new();
        buf.try_reserve_exact(total_size)
            .map_err(|e| format!("reserve {total_size} bytes for {kind:?}: {e}"))?;
        PendingBuf::Eager { buf, total_size }
    };
    *lock_pending(kind) = Some(pending);
    Ok(())
}

fn load_pk_chunk_core(kind: CircuitKind, chunk: &[u8]) -> Result<(), String> {
    let mut guard = lock_pending(kind);
    let pending = guard
        .as_mut()
        .ok_or_else(|| format!("load_pk_chunk before load_pk_begin for {kind:?}"))?;
    match pending {
        PendingBuf::Eager { buf, total_size } => {
            let next_len = buf.len().saturating_add(chunk.len());
            if next_len > *total_size {
                return Err(format!(
                    "chunk exceeds announced total for {kind:?}: would be {next_len}, total {total_size}",
                ));
            }
            buf.extend_from_slice(chunk);
        }
        PendingBuf::Streaming {
            chunks,
            total_size,
            len,
        } => {
            let next_len = len.saturating_add(chunk.len());
            if next_len > *total_size {
                return Err(format!(
                    "chunk exceeds announced total for {kind:?}: would be {next_len}, total {total_size}",
                ));
            }
            chunks.push_back(chunk.to_vec());
            *len = next_len;
        }
    }
    Ok(())
}

fn load_pk_finish_core(kind: CircuitKind) -> Result<(), String> {
    let pending = lock_pending(kind)
        .take()
        .ok_or_else(|| format!("load_pk_finish before load_pk_begin for {kind:?}"))?;
    let pk = match pending {
        PendingBuf::Eager { buf, .. } => bincode::deserialize(&buf)
            .map_err(|e| format!("PK deserialize ({kind:?}): {e}"))?,
        PendingBuf::Streaming { chunks, .. } => {
            let reader = ChunkDrainReader { chunks, front_off: 0 };
            bincode::deserialize_from(reader)
                .map_err(|e| format!("PK deserialize streaming ({kind:?}): {e}"))?
        }
    };
    *lock_pk_mut(kind) = Some(pk);
    Ok(())
}

/// Begin a streaming PK load. `low_memory_mode` picks the storage shape:
///
/// * `false` (eager): one pre-reserved `Vec<u8>`, deserialized from a
///   slice. Fastest per byte; wasm peak holds the raw buffer alongside
///   the `ProverKey` being built.
/// * `true` (streaming): each chunk is its own `Vec<u8>`; finalize reads
///   through a draining `Read` adapter that drops each chunk once
///   consumed so the wasm allocator can reuse the freed capacity for
///   `ProverKey` allocations still in flight. Slower per byte but cuts
///   the transient peak. Use under the iOS WKWebView WebContent jetsam
///   cap; non-web binding consumers use `load_pk(bytes)` and don't touch
///   this path.
#[wasm_bindgen]
pub fn load_pk_begin(
    kind: CircuitKind,
    total_size: usize,
    low_memory_mode: bool,
) -> Result<(), JsError> {
    load_pk_begin_core(kind, total_size, low_memory_mode).map_err(|e| JsError::new(&e))
}

/// Append a chunk to the in-flight buffer. The cumulative length is bounded
/// by the `total_size` announced in `load_pk_begin` so a caller cannot quietly
/// overshoot (which would force a reallocation in eager mode and a silent
/// drift between announced and actual bytes in streaming mode).
#[wasm_bindgen]
pub fn load_pk_chunk(kind: CircuitKind, chunk: &[u8]) -> Result<(), JsError> {
    load_pk_chunk_core(kind, chunk).map_err(|e| JsError::new(&e))
}

/// Deserialize the accumulated bytes into a ProverKey and stash it. The
/// in-flight buffer is moved out of the static so a finalize failure
/// leaves no leftover state for the next attempt.
#[wasm_bindgen]
pub fn load_pk_finish(kind: CircuitKind) -> Result<(), JsError> {
    load_pk_finish_core(kind).map_err(|e| JsError::new(&e))
}

/// Discard the in-flight buffer without finalizing. Safe to call when no
/// load is in flight.
#[wasm_bindgen]
pub fn load_pk_cancel(kind: CircuitKind) {
    *lock_pending(kind) = None;
}

#[wasm_bindgen]
pub fn drop_pk(kind: CircuitKind) { *lock_pk_mut(kind) = None; }

#[derive(Serialize)]
struct ProveJs { proof: Vec<u8>, instance: Vec<u8>, public_values: Vec<String> }

#[wasm_bindgen]
pub fn prove(kind: CircuitKind, wtns_bytes: &[u8]) -> Result<JsValue, JsError> {
    let guard = lock_pk_mut(kind);
    let pk = guard.as_ref().ok_or_else(|| JsError::new("PK not loaded. Call load_pk() first."))?;
    let (proof, instance, pv) = prove_core(pk, kind, wtns_bytes).map_err(|e| JsError::new(&e))?;
    let out = ProveJs {
        proof, instance,
        public_values: pv.iter().map(|s| format!("{s:?}")).collect(),
    };
    serde_wasm_bindgen::to_value(&out).map_err(|e| JsError::new(&e.to_string()))
}

#[derive(Serialize)]
struct VerifyJs { valid: bool, public_values: Vec<String>, error: Option<String> }

#[wasm_bindgen]
pub fn verify(proof_bytes: &[u8], vk_bytes: &[u8]) -> Result<JsValue, JsError> {
    let proof: R1CSSNARK<E> = bincode::deserialize(proof_bytes)
        .map_err(|e| JsError::new(&format!("proof deserialize: {e}")))?;
    let vk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey = bincode::deserialize(vk_bytes)
        .map_err(|e| JsError::new(&format!("vk deserialize: {e}")))?;
    let out = match proof.verify(&vk) {
        Ok(pv) => VerifyJs {
            valid: true,
            public_values: pv.iter().map(|s| format!("{s:?}")).collect(),
            error: None,
        },
        Err(e) => VerifyJs { valid: false, public_values: vec![], error: Some(format!("{e:?}")) },
    };
    serde_wasm_bindgen::to_value(&out).map_err(|e| JsError::new(&e.to_string()))
}

/// Assert pk_commit equality between a cert-chain proof's public values and a
/// user-sig proof's public values. Both are passed as Vec<String> (debug-printed
/// scalars) to match what `prove()` and `verify()` return to JS.
#[wasm_bindgen]
pub fn link_verify(cert_pubs: Vec<String>, user_sig_pubs: Vec<String>) -> Result<JsValue, JsError> {
    let cert_pk = cert_pubs.get(CircuitKind::CertChainRs2048.pk_commit_index())
        .ok_or_else(|| JsError::new("cert public values missing pkCommit"))?;
    let user_sig_pk = user_sig_pubs.get(CircuitKind::UserSigRs2048.pk_commit_index())
        .ok_or_else(|| JsError::new("user-sig public values missing pkCommit"))?;
    let ok = cert_pk == user_sig_pk;
    #[derive(Serialize)]
    struct LinkJs { ok: bool, cert_pk_commit: String, user_sig_pk_commit: String }
    serde_wasm_bindgen::to_value(&LinkJs {
        ok, cert_pk_commit: cert_pk.clone(), user_sig_pk_commit: user_sig_pk.clone(),
    }).map_err(|e| JsError::new(&e.to_string()))
}

// ── Native-only API for the drift test ───────────────────────────────────────
#[cfg(not(target_arch = "wasm32"))]
pub fn prove_native_for_test(
    kind: CircuitKind, pk_bytes: &[u8], wtns_bytes: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<Scalar>), String> {
    let pk = bincode::deserialize(pk_bytes).map_err(|e| format!("pk deserialize: {e}"))?;
    prove_core(&pk, kind, wtns_bytes)
}

/// Load a PK via the streaming triple under `low_memory_mode` and return
/// the re-serialized loaded PK. Native-only test helper for cross-mode
/// round-trip parity.
#[cfg(not(target_arch = "wasm32"))]
pub fn load_pk_via_streaming_for_test(
    kind: CircuitKind,
    pk_bytes: &[u8],
    chunk_size: usize,
    low_memory_mode: bool,
) -> Result<Vec<u8>, String> {
    load_pk_cancel(kind);
    drop_pk(kind);
    load_pk_begin_core(kind, pk_bytes.len(), low_memory_mode)?;
    for chunk in pk_bytes.chunks(chunk_size) {
        load_pk_chunk_core(kind, chunk)?;
    }
    load_pk_finish_core(kind)?;
    let guard = lock_pk_mut(kind);
    let pk = guard
        .as_ref()
        .ok_or_else(|| format!("pk slot empty after load_pk_finish for {kind:?}"))?;
    bincode::serialize(pk).map_err(|e| format!("re-serialize: {e}"))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn verify_roundtrip(
    proof_bytes: &[u8], vk_bytes: &[u8],
) -> Result<Vec<Scalar>, String> {
    let proof: R1CSSNARK<E> = bincode::deserialize(proof_bytes).map_err(|e| e.to_string())?;
    let vk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey =
        bincode::deserialize(vk_bytes).map_err(|e| e.to_string())?;
    proof.verify(&vk).map_err(|e| format!("{e:?}"))
}

// ── Unit tests (native; parse_witness edge cases) ────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn parse_witness_bad_magic() {
        assert!(parse_witness(b"XXXX\x00\x00\x00\x00\x02\x00\x00\x00").is_err());
    }
    #[test] fn parse_witness_truncated() {
        assert!(parse_witness(b"wtns\x01\x00\x00\x00").is_err());
    }
    #[test] fn parse_witness_empty() {
        assert!(parse_witness(&[]).is_err());
    }
    #[test] fn num_public_matches_spec() {
        assert_eq!(CircuitKind::CertChainRs2048.num_public(), 20);
        assert_eq!(CircuitKind::CertChainRs4096.num_public(), 37);
        assert_eq!(CircuitKind::UserSigRs2048.num_public(), 4);
    }

    /// Regression: oversized section lengths must return Err, not panic.
    #[test] fn parse_witness_oversized_section_length_no_overflow() {
        // Valid magic (4) + version (4) + n_sections=1 (4) = 12
        // + section_id=2 (4) + section_length=usize::MAX (8) = 24
        let mut bytes = Vec::from(&b"wtns\x02\x00\x00\x00\x01\x00\x00\x00"[..]);
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(parse_witness(&bytes).is_err());
    }

    /// Reset before/after each streaming test so a prior failure cannot
    /// leak in-flight state. `load_pk_cancel` itself doesn't construct a
    /// JsError so it's safe to call from native tests.
    fn reset_streaming(kind: CircuitKind) {
        load_pk_cancel(kind);
    }

    /// Drain the pending slot to a flat Vec regardless of variant.
    fn drain_pending_to_vec(kind: CircuitKind) -> Vec<u8> {
        let mut guard = lock_pending(kind);
        match guard.take().expect("pending set") {
            PendingBuf::Eager { buf, .. } => buf,
            PendingBuf::Streaming { chunks, .. } => {
                let mut reader = ChunkDrainReader { chunks, front_off: 0 };
                let mut out = Vec::new();
                reader.read_to_end(&mut out).expect("drain reader");
                out
            }
        }
    }

    #[test]
    fn load_pk_chunk_before_begin_errors() {
        reset_streaming(CircuitKind::UserSigRs2048);
        assert!(load_pk_chunk_core(CircuitKind::UserSigRs2048, &[1, 2, 3]).is_err());
    }

    #[test]
    fn load_pk_finish_before_begin_errors() {
        reset_streaming(CircuitKind::CertChainRs2048);
        assert!(load_pk_finish_core(CircuitKind::CertChainRs2048).is_err());
    }

    fn check_chunk_capacity_overflow_errors(low_memory_mode: bool) {
        reset_streaming(CircuitKind::CertChainRs4096);
        load_pk_begin_core(CircuitKind::CertChainRs4096, 4, low_memory_mode).unwrap();
        load_pk_chunk_core(CircuitKind::CertChainRs4096, &[1, 2, 3]).unwrap();
        assert!(
            load_pk_chunk_core(CircuitKind::CertChainRs4096, &[4, 5, 6]).is_err(),
            "low_memory_mode={low_memory_mode}",
        );
        reset_streaming(CircuitKind::CertChainRs4096);
    }

    #[test]
    fn load_pk_chunk_capacity_overflow_errors_eager() {
        check_chunk_capacity_overflow_errors(false);
    }

    #[test]
    fn load_pk_chunk_capacity_overflow_errors_streaming() {
        check_chunk_capacity_overflow_errors(true);
    }

    fn check_cancel_clears_pending(low_memory_mode: bool) {
        reset_streaming(CircuitKind::UserSigRs2048);
        load_pk_begin_core(CircuitKind::UserSigRs2048, 8, low_memory_mode).unwrap();
        load_pk_chunk_core(CircuitKind::UserSigRs2048, &[1, 2, 3, 4]).unwrap();
        load_pk_cancel(CircuitKind::UserSigRs2048);
        assert!(load_pk_finish_core(CircuitKind::UserSigRs2048).is_err());
        assert!(load_pk_chunk_core(CircuitKind::UserSigRs2048, &[5]).is_err());
    }

    #[test]
    fn load_pk_cancel_clears_pending_eager() {
        check_cancel_clears_pending(false);
    }

    #[test]
    fn load_pk_cancel_clears_pending_streaming() {
        check_cancel_clears_pending(true);
    }

    fn check_begin_resets_previous_buffer(first_mode: bool, second_mode: bool) {
        reset_streaming(CircuitKind::CertChainRs2048);
        load_pk_begin_core(CircuitKind::CertChainRs2048, 16, first_mode).unwrap();
        load_pk_chunk_core(CircuitKind::CertChainRs2048, &[0; 8]).unwrap();
        // A second begin throws away the partially-filled state; the
        // following chunk fits the new total rather than the old offset.
        load_pk_begin_core(CircuitKind::CertChainRs2048, 4, second_mode).unwrap();
        load_pk_chunk_core(CircuitKind::CertChainRs2048, &[1, 2, 3, 4]).unwrap();
        assert!(load_pk_chunk_core(CircuitKind::CertChainRs2048, &[5]).is_err());
        reset_streaming(CircuitKind::CertChainRs2048);
    }

    #[test]
    fn load_pk_begin_resets_previous_buffer_eager() {
        check_begin_resets_previous_buffer(false, false);
    }

    #[test]
    fn load_pk_begin_resets_previous_buffer_streaming() {
        check_begin_resets_previous_buffer(true, true);
    }

    #[test]
    fn load_pk_begin_resets_previous_buffer_mode_switch() {
        check_begin_resets_previous_buffer(false, true);
        check_begin_resets_previous_buffer(true, false);
    }

    fn check_chunks_accumulate_bytes_in_order(low_memory_mode: bool) {
        reset_streaming(CircuitKind::CertChainRs4096);
        let original: Vec<u8> = (0u8..=255).cycle().take(1000).collect();
        load_pk_begin_core(CircuitKind::CertChainRs4096, original.len(), low_memory_mode)
            .unwrap();
        for chunk in original.chunks(37) {
            load_pk_chunk_core(CircuitKind::CertChainRs4096, chunk).unwrap();
        }
        assert_eq!(drain_pending_to_vec(CircuitKind::CertChainRs4096), original);
        reset_streaming(CircuitKind::CertChainRs4096);
    }

    /// Regression: chunks must concatenate in call order with no overlap
    /// or gap so finalize sees byte-identical input to the one-shot
    /// `load_pk(kind, &bytes)` path.
    #[test]
    fn streaming_chunks_accumulate_bytes_in_order_eager() {
        check_chunks_accumulate_bytes_in_order(false);
    }

    #[test]
    fn streaming_chunks_accumulate_bytes_in_order_streaming() {
        check_chunks_accumulate_bytes_in_order(true);
    }

    #[test]
    fn chunk_drain_reader_yields_bytes_in_order_across_chunks() {
        let mut chunks = VecDeque::new();
        chunks.push_back(vec![1u8, 2, 3]);
        chunks.push_back(vec![4u8, 5]);
        chunks.push_back(vec![6u8]);
        let mut reader = ChunkDrainReader { chunks, front_off: 0 };
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn chunk_drain_reader_short_reads_then_long_read() {
        let mut chunks = VecDeque::new();
        chunks.push_back(vec![1u8, 2, 3]);
        chunks.push_back((10u8..=109).collect::<Vec<u8>>());
        let mut reader = ChunkDrainReader { chunks, front_off: 0 };
        let mut buf = [0u8; 1];
        assert_eq!(reader.read(&mut buf).unwrap(), 1);
        assert_eq!(buf, [1]);
        let mut big = vec![0u8; 100];
        let n = reader.read(&mut big).unwrap();
        assert_eq!(n, 100);
        assert_eq!(&big[..2], &[2, 3]);
        assert_eq!(big[2], 10);
        assert_eq!(big[99], 107);
        let mut tail = Vec::new();
        reader.read_to_end(&mut tail).unwrap();
        assert_eq!(tail, vec![108, 109]);
    }

    #[test]
    fn chunk_drain_reader_drops_consumed_chunks() {
        let mut chunks = VecDeque::new();
        chunks.push_back(vec![1u8, 2, 3]);
        chunks.push_back(vec![4u8, 5, 6]);
        chunks.push_back(vec![7u8, 8, 9]);
        let mut reader = ChunkDrainReader { chunks, front_off: 0 };
        let mut buf = vec![0u8; 4];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(buf, vec![1, 2, 3, 4]);
        assert_eq!(reader.chunks.len(), 2, "chunk 0 must be dropped");
        assert_eq!(reader.front_off, 1, "1 byte consumed from new front");
    }

    #[test]
    fn load_pk_begin_low_memory_mode_skips_reservation() {
        reset_streaming(CircuitKind::CertChainRs4096);
        // 256 GB would fail `Vec::try_reserve_exact` on any host; streaming
        // mode never reserves, so begin must still succeed.
        let huge = 256usize * 1024 * 1024 * 1024;
        assert!(
            load_pk_begin_core(CircuitKind::CertChainRs4096, huge, true).is_ok(),
            "streaming mode must not pre-reserve",
        );
        reset_streaming(CircuitKind::CertChainRs4096);
    }
}

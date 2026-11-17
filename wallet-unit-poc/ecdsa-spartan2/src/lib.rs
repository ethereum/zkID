//! RS256 (RSA-SHA256) certificate circuits using Spartan2.
//!
//! Zero-knowledge proofs for X.509 certificate verification (split cert-chain and
//! user-signature circuits) using Spartan2 with Hyrax polynomial commitments.

use spartan2::{provider::T256HyraxEngine, traits::Engine};

pub type E = T256HyraxEngine;
pub type Scalar = <E as Engine>::Scalar;

/// Default TBS challenge used by test fixtures and CLI defaults.
pub const DEFAULT_TBS: &[u8] = b"e775f2805fb993e05a208dbff15d1c1";

/// Default per-session challenge field element for fixture / non-live runs;
/// keeps committed input JSONs byte-deterministic. Live runs replace it with
/// the verifier's value.
pub const DEFAULT_CHALLENGE: &str = "1339673755198158349044581307228491536";

/// Default `currentTime` (`YYMMDDHHMMSS`, UTC) for fixture / non-live runs:
/// 2026-11-14 15:59:59, inside the validity period of both bundled fixture
/// certs. Live runs use the system clock.
pub const DEFAULT_CURRENT_TIME: &str = "261114155959";

pub mod challenge_client;
pub mod circuits;
pub mod hipki_client;
pub mod paths;
pub mod prover;
pub mod reader;
pub mod setup;
pub mod smt_client;
pub mod utils;

pub use circuits::cert::serial_bytes_to_hex_trimmed;
pub use circuits::circuit::{RsaKeySize, Sha256RsaCircuit};
pub use circuits::split_circuits::{
    generate_split_inputs, random_pk_blind, CertChainCircuit, CertChainRs4096Circuit,
    CertChainRsa2048, CertChainRsa4096, UserSigCircuit, UserSigRsa2048, APP_ID_LEN,
    MAX_CERT_CHAIN_LENGTH,
};
pub use paths::PathConfig;
pub use zkid_input_builder::current_time_utc;
pub use prover::{
    prove_circuit, prove_circuit_in_memory, prove_circuit_with_pk, reblind, reblind_in_memory,
    reblind_with_loaded_data, run_circuit, verify_circuit, verify_circuit_with_loaded_data,
};
pub use setup::{
    load_instance, load_proof, load_proving_key, load_shared_blinds, load_verifying_key,
    load_witness, save_keys, setup_circuit_keys, setup_circuit_keys_no_save,
};
pub use utils::{bigint_to_scalar, convert_bigint_to_scalar};

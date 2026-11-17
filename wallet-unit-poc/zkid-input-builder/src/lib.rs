//! Shared input builder for the zkID RS256 split circuits.
//!
//! Produces cert-chain + user-sig JSON inputs from raw certificate DER,
//! signatures, and SMT non-membership proof. Consumed by `ecdsa-spartan2`
//! (native prover) and `spartan2-wasm` (in-browser prover) so both paths
//! produce byte-identical JSON — which is the safeguard against reintroducing
//! witness-input shape errors such as
//! "Too many values for input signal __placeholder__".

pub mod cert;
pub mod encoding;
pub mod random;
pub mod split_inputs;
pub mod time;
pub mod types;

pub use random::random_pk_blind;
pub use split_inputs::{generate_split_inputs, APP_ID_LEN, MAX_CERT_CHAIN_LENGTH};
#[cfg(not(target_arch = "wasm32"))]
pub use time::current_time_utc;
pub use time::format_current_time;

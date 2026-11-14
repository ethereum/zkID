//! Canonical reference implementation for the cert-chain + user-sig circuit
//! input JSON. Native (`ecdsa-spartan2`) and in-browser (`spartan2-wasm`)
//! provers both call through here; `spartan2-wasm/tests/input_builder_drift.rs`
//! pins the two callers to byte-identical output.

use crate::encoding::{
    bigint_to_chunks, sha256_pad, sha256_padded_length, smt_fields_from_option,
};
use crate::types::SmtCircuitInputs;
use base64::Engine as _;
use der::Encode;
use num_bigint::BigUint;
use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts, RsaPublicKey};
use x509_cert::Certificate;

const RSA_N: usize = 121;
pub const MAX_CERT_CHAIN_LENGTH: usize = 1536;
const MAX_MESSAGE_LENGTH: usize = 1536;
const SMT_DEPTH: usize = 128;
pub const APP_ID_LEN: usize = 31;

/// Build the cert-chain + user-sig circuit input JSONs.
///
/// `pk_blind` is the per-session linking blind shared between Circuits A and B.
/// `challenge` is the per-session field element from the verifier's
/// `/challenge` endpoint, bound into the user-sig proof via a Semaphore-style
/// dummy square. Both are decimal field-element strings.
///
/// `current_time` is the verifier's time as the decimal integer `YYMMDDHHMMSS`
/// (UTC); the cert-chain circuit asserts it lies within the user cert's
/// validity period. See [`crate::current_time_utc`].
pub fn generate_split_inputs(
    user_cert: &Certificate,
    issuer_cert: &Certificate,
    user_signature_b64: &str,
    app_id_bytes: &[u8],
    serial_hex: &str,
    smt_inputs: Option<&SmtCircuitInputs>,
    k_issuer: usize,
    k_user: usize,
    max_cert_length: usize,
    pk_blind: &str,
    challenge: &str,
    current_time: &str,
) -> Result<(serde_json::Value, serde_json::Value), Box<dyn std::error::Error>> {
    if app_id_bytes.len() != APP_ID_LEN {
        return Err(format!(
            "app_id_bytes must be exactly {APP_ID_LEN} bytes, got {}",
            app_id_bytes.len()
        )
        .into());
    }
    let user_cert_tbs_der = user_cert.tbs_certificate.to_der()?;
    let user_spki_der = user_cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()?;
    let user_rsa_pub = RsaPublicKey::from_public_key_der(&user_spki_der)?;
    let user_modulus = BigUint::from_bytes_be(&user_rsa_pub.n().to_bytes_be());
    let user_pk_limbs = bigint_to_chunks(&user_modulus, k_user, RSA_N);

    let issuer_spki_der = issuer_cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()?;
    let issuer_rsa_pub = RsaPublicKey::from_public_key_der(&issuer_spki_der)?;
    let issuer_modulus = BigUint::from_bytes_be(&issuer_rsa_pub.n().to_bytes_be());
    let issuer_rsa_modulus = bigint_to_chunks(&issuer_modulus, k_issuer, RSA_N);

    let issuer_sig_bytes = user_cert.signature.raw_bytes();
    let issuer_sig_biguint = BigUint::from_bytes_be(issuer_sig_bytes);
    let issuer_rsa_signature = bigint_to_chunks(&issuer_sig_biguint, k_issuer, RSA_N);

    let user_sig_bytes =
        base64::engine::general_purpose::STANDARD.decode(user_signature_b64)?;
    let user_sig_biguint = BigUint::from_bytes_be(&user_sig_bytes);
    let user_rsa_signature = bigint_to_chunks(&user_sig_biguint, k_user, RSA_N);

    let tbs_padded: Vec<String> = sha256_pad(app_id_bytes, MAX_MESSAGE_LENGTH)
        .iter()
        .map(|b| b.to_string())
        .collect();
    let issuer_tbs_padded: Vec<String> =
        sha256_pad(&user_cert_tbs_der, max_cert_length)
            .iter()
            .map(|b| b.to_string())
            .collect();
    let issuer_tbs_padded_len = sha256_padded_length(user_cert_tbs_der.len());

    let serial_decimal = BigUint::parse_bytes(serial_hex.as_bytes(), 16)
        .ok_or_else(|| format!("serial_hex is not valid hex: {serial_hex:?}"))?
        .to_string();

    let (smt_root, smt_serial, smt_siblings, smt_old_key, smt_old_value, smt_is_old0) =
        smt_fields_from_option(smt_inputs, serial_decimal, SMT_DEPTH);

    let cert_chain_json = serde_json::json!({
        "issuerTbs": issuer_tbs_padded,
        "issuerTbsLength": issuer_tbs_padded_len,
        "actualIssuerTbsLength": user_cert_tbs_der.len(),
        "issuerRsaModulus": issuer_rsa_modulus,
        "issuerRsaSignature": issuer_rsa_signature,
        "smtRoot": smt_root,
        "serialNumber": smt_serial,
        "smtSiblings": smt_siblings,
        "smtOldKey": smt_old_key,
        "smtOldValue": smt_old_value,
        "smtIsOld0": smt_is_old0,
        "currentTime": current_time,
        "pkBlind": pk_blind,
    });

    let user_sig_json = serde_json::json!({
        "tbs": tbs_padded,
        "userPkLimbs": user_pk_limbs,
        "userRsaSignature": user_rsa_signature,
        "pkBlind": pk_blind,
        "challenge": challenge,
    });

    Ok((cert_chain_json, user_sig_json))
}

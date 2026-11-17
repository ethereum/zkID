//! Wasm entry points around `zkid_input_builder::generate_split_inputs`.
//! Byte-for-byte parity with the native caller is pinned by
//! `tests/input_builder_drift.rs`.

use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts, RsaPublicKey};
use serde::Serialize;
use serde_wasm_bindgen::Serializer;
use wasm_bindgen::prelude::*;
use x509_cert::{der::{Decode, Encode}, Certificate};
use zkid_input_builder::{
    cert::serial_bytes_to_hex_trimmed, generate_split_inputs, random_pk_blind,
    types::SmtCircuitInputs, APP_ID_LEN, MAX_CERT_CHAIN_LENGTH,
};

/// Two-JSON return shape. `cert_chain` + `user_sig` match the keys the
/// circom witness calculator expects in its input file.
#[derive(Serialize)]
pub struct SplitInputsJs {
    pub cert_chain: serde_json::Value,
    pub user_sig: serde_json::Value,
}

#[allow(clippy::too_many_arguments)]
fn build_split_inputs_core(
    user_cert_der: &[u8],
    issuer_cert_der: &[u8],
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
) -> Result<SplitInputsJs, String> {
    let user_cert = Certificate::from_der(user_cert_der)
        .map_err(|e| format!("user cert DER parse: {e}"))?;
    let issuer_cert = Certificate::from_der(issuer_cert_der)
        .map_err(|e| format!("issuer cert DER parse: {e}"))?;

    let (cert_chain, user_sig) = generate_split_inputs(
        &user_cert,
        &issuer_cert,
        user_signature_b64,
        app_id_bytes,
        serial_hex,
        smt_inputs,
        k_issuer,
        k_user,
        max_cert_length,
        pk_blind,
        challenge,
        current_time,
    )
    .map_err(|e| format!("generate_split_inputs: {e}"))?;

    Ok(SplitInputsJs {
        cert_chain,
        user_sig,
    })
}

/// `smt_inputs`: `null`/`undefined` fills zero defaults; otherwise a snake_case
/// `SmtCircuitInputs` object. `k_issuer` is 17 (RSA-2048) or 34 (RSA-4096);
/// `k_user` must be 17. `challenge` is the verifier-issued per-session field
/// element (decimal string) bound into the user-sig proof. `current_time` is
/// the decimal integer `YYMMDDHHMMSS` (UTC) the cert-chain proof checks the
/// certificate's validity period against.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn build_split_inputs(
    user_cert_der: &[u8],
    issuer_cert_der: &[u8],
    user_signature_b64: &str,
    app_id_bytes: &[u8],
    serial_hex: &str,
    smt_inputs: JsValue,
    k_issuer: u32,
    k_user: u32,
    challenge: &str,
    current_time: &str,
) -> Result<JsValue, JsError> {
    if k_issuer != 17 && k_issuer != 34 {
        return Err(JsError::new(&format!(
            "unsupported k_issuer {k_issuer}; expected 17 (RSA-2048) or 34 (RSA-4096)"
        )));
    }
    if k_user != 17 {
        return Err(JsError::new(&format!(
            "unsupported k_user {k_user}; MOICA user keys are RSA-2048 (k_user=17)"
        )));
    }
    if app_id_bytes.len() != APP_ID_LEN {
        return Err(JsError::new(&format!(
            "app_id_bytes must be {APP_ID_LEN} bytes, got {}",
            app_id_bytes.len()
        )));
    }

    let smt: Option<SmtCircuitInputs> = if smt_inputs.is_null() || smt_inputs.is_undefined() {
        None
    } else {
        Some(
            serde_wasm_bindgen::from_value(smt_inputs)
                .map_err(|e| JsError::new(&format!("smt_inputs parse: {e}")))?,
        )
    };

    let pk_blind = random_pk_blind();
    let out = build_split_inputs_core(
        user_cert_der,
        issuer_cert_der,
        user_signature_b64,
        app_id_bytes,
        serial_hex,
        smt.as_ref(),
        k_issuer as usize,
        k_user as usize,
        MAX_CERT_CHAIN_LENGTH,
        &pk_blind,
        challenge,
        current_time,
    )
    .map_err(|e| JsError::new(&e))?;

    // `serde_json::Value::Object` would otherwise serialise to a JS `Map`, and
    // `JSON.stringify(map)` returns `"{}"` — the witness calc sees zero inputs.
    let serializer = Serializer::new().serialize_maps_as_objects(true);
    out.serialize(&serializer)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// RSA modulus bit width of the cert's `subjectPublicKey`. Used by the web
/// app to pick `certChainRS2048` vs `certChainRS4096` from the real
/// issuer key, rather than guessing from the issuer DN string.
#[wasm_bindgen]
pub fn cert_modulus_bits(cert_der: &[u8]) -> Result<u32, JsError> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| JsError::new(&format!("cert DER parse: {e}")))?;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| JsError::new(&format!("SPKI encode: {e}")))?;
    let pubkey = RsaPublicKey::from_public_key_der(&spki_der)
        .map_err(|e| JsError::new(&format!("not an RSA cert: {e}")))?;
    Ok(pubkey.n().bits() as u32)
}

/// Trimmed-hex serial of an X.509 cert. Called after HiPKI `/sign` returns —
/// that cert may differ from the `/pkcs11info` entry, and the circuit keys
/// off the signing cert's serial.
#[wasm_bindgen]
pub fn cert_serial_hex(cert_der: &[u8]) -> Result<String, JsError> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| JsError::new(&format!("cert DER parse: {e}")))?;
    Ok(serial_bytes_to_hex_trimmed(
        cert.tbs_certificate.serial_number.as_bytes(),
    ))
}

/// Native-target entry for the drift integration test. Never compiled for
/// wasm32 — the public `build_split_inputs` is the only exported surface.
#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::too_many_arguments)]
pub fn build_split_inputs_native_for_test(
    user_cert_der: &[u8],
    issuer_cert_der: &[u8],
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
) -> Result<SplitInputsJs, String> {
    build_split_inputs_core(
        user_cert_der,
        issuer_cert_der,
        user_signature_b64,
        app_id_bytes,
        serial_hex,
        smt_inputs,
        k_issuer,
        k_user,
        max_cert_length,
        pk_blind,
        challenge,
        current_time,
    )
}

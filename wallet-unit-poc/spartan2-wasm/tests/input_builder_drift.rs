//! Drift guard: spartan2-wasm's native entry must produce byte-identical JSON
//! to `ecdsa-spartan2`'s `generate_split_inputs`. A one-byte drift would
//! resurface witness-input shape errors at proving time. Native target only.

#![cfg(not(target_arch = "wasm32"))]

use ecdsa_spartan2::{
    circuits::{
        cert::{extract_issuer_cert, generate_user_cert_from_certb64, serial_bytes_to_hex_trimmed},
        types::{CardSignResponse, Pkcs11InfoResponse, Rs4096SignResponse, SmtCircuitInputs},
    },
    generate_split_inputs, DEFAULT_CHALLENGE, DEFAULT_CURRENT_TIME, DEFAULT_TBS, MAX_CERT_CHAIN_LENGTH,
};
use spartan2_wasm::inputs::build_split_inputs_native_for_test;
use x509_cert::{
    der::{Decode, Encode},
    Certificate,
};

/// Same constant as ecdsa-spartan2/tests/split_input_generation.rs so all
/// committed test JSONs share the same blind. `DEFAULT_CHALLENGE` is reused
/// from `ecdsa_spartan2` directly.
const TEST_PK_BLIND: &str =
    "452312848583266388373324160190187140051835877600158453279131187530910662655";

const SIGN_RESPONSE_PATH: &str = "../ecdsa-spartan2/tests/testdata/response_sign_test.json";
const PKCS11_RESPONSE_PATH: &str = "../ecdsa-spartan2/tests/testdata/pkcs11info_test.json";
const RS4096_SIGN_RESPONSE_PATH: &str =
    "../ecdsa-spartan2/tests/testdata/rs4096_response_sign.json";
const RS4096_CA_PATH: &str = "../ecdsa-spartan2/tests/testdata/test_ca_rs4096.der";

fn rs2048_fixtures() -> (Vec<u8>, Vec<u8>, String, String) {
    let sign: CardSignResponse = serde_json::from_str(
        &std::fs::read_to_string(SIGN_RESPONSE_PATH).expect("read sign fixture"),
    )
    .expect("parse sign fixture");

    let pkcs11: Pkcs11InfoResponse = serde_json::from_str(
        &std::fs::read_to_string(PKCS11_RESPONSE_PATH).expect("read pkcs11 fixture"),
    )
    .expect("parse pkcs11 fixture");

    let user_cert = generate_user_cert_from_certb64(&sign.certb64).expect("user cert");
    let issuer_cert = extract_issuer_cert(&pkcs11).expect("issuer cert");

    let serial_hex =
        serial_bytes_to_hex_trimmed(user_cert.tbs_certificate.serial_number.as_bytes());

    (
        user_cert.to_der().expect("user DER"),
        issuer_cert.to_der().expect("issuer DER"),
        sign.signature,
        serial_hex,
    )
}

fn rs4096_fixtures() -> (Vec<u8>, Vec<u8>, String, String) {
    let response: Rs4096SignResponse = serde_json::from_str(
        &std::fs::read_to_string(RS4096_SIGN_RESPONSE_PATH).expect("read RS4096 sign fixture"),
    )
    .expect("parse RS4096 sign fixture");

    let issuer_cert =
        Certificate::from_der(&std::fs::read(RS4096_CA_PATH).expect("read RS4096 CA DER"))
            .expect("parse RS4096 CA");
    let user_cert = generate_user_cert_from_certb64(&response.result.cert).expect("user cert");
    let serial_hex =
        serial_bytes_to_hex_trimmed(user_cert.tbs_certificate.serial_number.as_bytes());

    (
        user_cert.to_der().expect("user DER"),
        issuer_cert.to_der().expect("issuer DER"),
        response.result.signed_response,
        serial_hex,
    )
}

fn assert_split_inputs_match(
    kind: &str,
    user_der: &[u8],
    issuer_der: &[u8],
    sig_b64: &str,
    serial_hex: &str,
    smt_inputs: Option<&SmtCircuitInputs>,
    k_issuer: usize,
) {
    let user_cert = Certificate::from_der(user_der).expect("user parse");
    let issuer_cert = Certificate::from_der(issuer_der).expect("issuer parse");

    let (native_cert, native_user_sig) = generate_split_inputs(
        &user_cert, &issuer_cert, sig_b64, DEFAULT_TBS, serial_hex,
        smt_inputs, k_issuer, 17, MAX_CERT_CHAIN_LENGTH,
        TEST_PK_BLIND, DEFAULT_CHALLENGE, DEFAULT_CURRENT_TIME,
    )
    .expect("native generate_split_inputs");

    let wasm_out = build_split_inputs_native_for_test(
        user_der, issuer_der, sig_b64, DEFAULT_TBS, serial_hex,
        smt_inputs, k_issuer, 17, MAX_CERT_CHAIN_LENGTH,
        TEST_PK_BLIND, DEFAULT_CHALLENGE, DEFAULT_CURRENT_TIME,
    )
    .expect("wasm crate build_split_inputs");

    assert_eq!(
        serde_json::to_string(&native_cert).unwrap(),
        serde_json::to_string(&wasm_out.cert_chain).unwrap(),
        "{kind}: cert_chain input JSON drifted between ecdsa-spartan2 and spartan2-wasm"
    );
    assert_eq!(
        serde_json::to_string(&native_user_sig).unwrap(),
        serde_json::to_string(&wasm_out.user_sig).unwrap(),
        "{kind}: user_sig input JSON drifted between ecdsa-spartan2 and spartan2-wasm"
    );
}

/// Synthesize an SMT non-membership proof shape matching the live server's
/// circuit-input output. Populates every field with a distinct non-zero
/// decimal so a mis-wired field would shift the final JSON.
fn synthetic_smt_inputs() -> SmtCircuitInputs {
    let mut siblings = vec!["0".to_string(); 128];
    for (i, slot) in siblings.iter_mut().enumerate().take(6) {
        *slot = format!("{}", 100 + i);
    }
    SmtCircuitInputs {
        smt_root: "42".to_string(),
        serial_number: "9999".to_string(),
        smt_siblings: siblings,
        smt_old_key: "7".to_string(),
        smt_old_value: "11".to_string(),
        smt_is_old0: "0".to_string(),
    }
}

#[test]
fn cert_chain_rs2048_input_builder_drift() {
    let (user_der, issuer_der, sig_b64, serial_hex) = rs2048_fixtures();
    assert_split_inputs_match(
        "rs2048", &user_der, &issuer_der, &sig_b64, &serial_hex, None, 17,
    );
}

#[test]
fn cert_chain_rs4096_input_builder_drift() {
    let (user_der, issuer_der, sig_b64, serial_hex) = rs4096_fixtures();
    assert_split_inputs_match(
        "rs4096", &user_der, &issuer_der, &sig_b64, &serial_hex, None, 34,
    );
}

/// Exercises the `smt_inputs = Some(..)` marshalling path so a silent field
/// rename on `SmtCircuitInputs` (or a divergence between the wasm and native
/// deserializers) fails CI instead of reaching the browser.
#[test]
fn cert_chain_rs2048_input_builder_drift_with_smt() {
    let (user_der, issuer_der, sig_b64, serial_hex) = rs2048_fixtures();
    let smt = synthetic_smt_inputs();
    assert_split_inputs_match(
        "rs2048+smt",
        &user_der,
        &issuer_der,
        &sig_b64,
        &serial_hex,
        Some(&smt),
        17,
    );
}

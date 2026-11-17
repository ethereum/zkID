//! Tests for `generate_split_inputs` — verifies the split input JSONs have
//! correct structure and that pk_blind is shared between cert-chain and
//! user-sig outputs.

use ecdsa_spartan2::{
    generate_split_inputs,
    circuits::types::{CardSignResponse, Pkcs11InfoResponse},
    CertChainCircuit, CertChainRs4096Circuit, DEFAULT_CHALLENGE, DEFAULT_CURRENT_TIME, DEFAULT_TBS,
    MAX_CERT_CHAIN_LENGTH,
};

/// Fixed 248-bit constant ((1 << 248) - 1) so split-input tests stay
/// byte-deterministic across runs and across native/wasm builders.
const TEST_PK_BLIND: &str =
    "452312848583266388373324160190187140051835877600158453279131187530910662655";

fn load_rs2048_fixtures() -> (x509_cert::Certificate, String, x509_cert::Certificate, String) {
    let response_str = std::fs::read_to_string("tests/testdata/response_sign_test.json")
        .expect("response_sign_test.json not found — run `cargo run --example generate_fixtures`");
    let response: CardSignResponse =
        serde_json::from_str(&response_str).expect("invalid JSON in response_sign_test.json");

    let pkcs11_str = std::fs::read_to_string("tests/testdata/pkcs11info_test.json")
        .expect("pkcs11info_test.json not found — run `cargo run --example generate_fixtures`");
    let pkcs11: Pkcs11InfoResponse =
        serde_json::from_str(&pkcs11_str).expect("invalid JSON in pkcs11info_test.json");

    let issuer_cert =
        CertChainCircuit::extract_issuer_cert(&pkcs11).expect("failed to extract issuer cert");
    let user_cert = CertChainCircuit::generate_user_cert_from_certb64(&response.certb64)
        .expect("failed to parse user cert");

    let serial_bytes = user_cert.tbs_certificate.serial_number.as_bytes();
    let serial_hex = hex::encode(serial_bytes);

    (user_cert, response.signature, issuer_cert, serial_hex)
}

fn load_rs4096_fixtures() -> (x509_cert::Certificate, String, x509_cert::Certificate, String) {
    let issuer_cert = CertChainRs4096Circuit::fetch_cert_from_file("tests/testdata/test_ca_rs4096.der")
        .expect("test_ca_rs4096.der not found — run `cargo run --example generate_fixtures`");

    let response_str = std::fs::read_to_string("tests/testdata/rs4096_response_sign.json")
        .expect("rs4096_response_sign.json not found — run `cargo run --example generate_fixtures`");
    let response: ecdsa_spartan2::circuits::types::Rs4096SignResponse =
        serde_json::from_str(&response_str).expect("invalid JSON in rs4096_response_sign.json");

    let user_cert = CertChainRs4096Circuit::generate_user_cert_from_certb64(&response.result.cert)
        .expect("failed to parse RS4096 user cert");

    let serial_bytes = user_cert.tbs_certificate.serial_number.as_bytes();
    let serial_hex = hex::encode(serial_bytes);

    (user_cert, response.result.signed_response, issuer_cert, serial_hex)
}

#[test]
fn split_inputs_have_expected_structure() {
    let (user_cert, user_sig_b64, issuer_cert, serial_hex) = load_rs2048_fixtures();

    let (cert_chain, user_sig) = generate_split_inputs(
        &user_cert,
        &issuer_cert,
        &user_sig_b64,
        DEFAULT_TBS,
        &serial_hex,
        None,
        17,
        17,
        MAX_CERT_CHAIN_LENGTH,
        TEST_PK_BLIND,
        DEFAULT_CHALLENGE,
        DEFAULT_CURRENT_TIME,
    )
    .expect("generate_split_inputs failed");

    // cert_chain JSON must have all expected keys
    for key in [
        "issuerTbs",
        "issuerTbsLength",
        "actualIssuerTbsLength",
        "issuerRsaModulus",
        "issuerRsaSignature",
        "smtRoot",
        "serialNumber",
        "smtSiblings",
        "smtOldKey",
        "smtOldValue",
        "smtIsOld0",
        "currentTime",
        "pkBlind",
    ] {
        assert!(
            cert_chain.get(key).is_some(),
            "cert_chain missing key: {key}"
        );
    }

    // user_sig JSON must have all expected keys; app_id_bytes is gone
    // (recovered in-circuit by packing tbs[0..31]).
    for key in ["tbs", "userPkLimbs", "userRsaSignature", "pkBlind", "challenge"] {
        assert!(
            user_sig.get(key).is_some(),
            "user_sig missing key: {key}"
        );
    }
    assert!(
        user_sig.get("app_id_bytes").is_none(),
        "user_sig should no longer expose app_id_bytes"
    );
    assert_eq!(
        user_sig["challenge"].as_str().expect("challenge string"),
        DEFAULT_CHALLENGE,
        "challenge passthrough"
    );

    // Array dimensions
    assert_eq!(
        cert_chain["issuerTbs"].as_array().unwrap().len(),
        1536,
        "issuerTbs length (MAX_CERT_CHAIN_LENGTH)"
    );
    assert_eq!(
        cert_chain["issuerRsaModulus"].as_array().unwrap().len(),
        17,
        "issuerRsaModulus length (kIssuer=17)"
    );
    assert_eq!(
        cert_chain["smtSiblings"].as_array().unwrap().len(),
        128,
        "smtSiblings length (smtDepth=128)"
    );
    assert_eq!(
        user_sig["tbs"].as_array().unwrap().len(),
        1536,
        "tbs length (maxMessageLength=1536)"
    );
    assert_eq!(
        user_sig["userPkLimbs"].as_array().unwrap().len(),
        17,
        "userPkLimbs length (kUser=17)"
    );
    assert_eq!(
        user_sig["userRsaSignature"].as_array().unwrap().len(),
        17,
        "userRsaSignature length (kUser=17)"
    );
}

#[test]
fn split_inputs_reject_wrong_length_app_id() {
    let (user_cert, user_sig_b64, issuer_cert, serial_hex) = load_rs2048_fixtures();
    let too_short: &[u8] = b"only30bytesnotthirtyonebytesss";
    assert_eq!(too_short.len(), 30);
    let result = generate_split_inputs(
        &user_cert,
        &issuer_cert,
        &user_sig_b64,
        too_short,
        &serial_hex,
        None,
        17,
        17,
        MAX_CERT_CHAIN_LENGTH,
        TEST_PK_BLIND,
        DEFAULT_CHALLENGE,
        DEFAULT_CURRENT_TIME,
    );
    assert!(result.is_err(), "30-byte app_id should be rejected");
}

#[test]
fn split_inputs_share_pk_blind() {
    let (user_cert, user_sig_b64, issuer_cert, serial_hex) = load_rs2048_fixtures();

    let (cert_chain, user_sig) = generate_split_inputs(
        &user_cert,
        &issuer_cert,
        &user_sig_b64,
        DEFAULT_TBS,
        &serial_hex,
        None,
        17,
        17,
        MAX_CERT_CHAIN_LENGTH,
        TEST_PK_BLIND,
        DEFAULT_CHALLENGE,
        DEFAULT_CURRENT_TIME,
    )
    .expect("generate_split_inputs failed");

    let cc_blind = cert_chain["pkBlind"].as_str().expect("cert_chain pkBlind not a string");
    let ds_blind = user_sig["pkBlind"].as_str().expect("user_sig pkBlind not a string");
    assert_eq!(
        cc_blind, ds_blind,
        "pkBlind must be identical across cert-chain and user-sig outputs"
    );
}

#[test]
fn split_inputs_rs4096_have_expected_structure() {
    let (user_cert, user_sig_b64, issuer_cert, serial_hex) = load_rs4096_fixtures();

    let (cert_chain, user_sig) = generate_split_inputs(
        &user_cert,
        &issuer_cert,
        &user_sig_b64,
        DEFAULT_TBS,
        &serial_hex,
        None,
        34,
        17,
        MAX_CERT_CHAIN_LENGTH,
        TEST_PK_BLIND,
        DEFAULT_CHALLENGE,
        DEFAULT_CURRENT_TIME,
    )
    .expect("generate_split_inputs failed for RS4096");

    // cert_chain JSON must have all expected keys
    for key in [
        "issuerTbs",
        "issuerTbsLength",
        "actualIssuerTbsLength",
        "issuerRsaModulus",
        "issuerRsaSignature",
        "smtRoot",
        "serialNumber",
        "smtSiblings",
        "smtOldKey",
        "smtOldValue",
        "smtIsOld0",
        "currentTime",
        "pkBlind",
    ] {
        assert!(
            cert_chain.get(key).is_some(),
            "cert_chain (RS4096) missing key: {key}"
        );
    }

    // user_sig JSON must have all expected keys
    for key in ["tbs", "userPkLimbs", "userRsaSignature", "pkBlind", "challenge"] {
        assert!(
            user_sig.get(key).is_some(),
            "user_sig (RS4096) missing key: {key}"
        );
    }
    assert!(
        user_sig.get("app_id_bytes").is_none(),
        "user_sig (RS4096) should no longer expose app_id_bytes"
    );

    // Array dimensions — 4096 params: cert padding=1536, k_issuer=34, k_user=17
    assert_eq!(
        cert_chain["issuerTbs"].as_array().unwrap().len(),
        1536,
        "issuerTbs length (MAX_CERT_CHAIN_LENGTH)"
    );
    assert_eq!(
        cert_chain["issuerRsaModulus"].as_array().unwrap().len(),
        34,
        "issuerRsaModulus length (kIssuer=34)"
    );
    assert_eq!(
        cert_chain["issuerRsaSignature"].as_array().unwrap().len(),
        34,
        "issuerRsaSignature length (kIssuer=34)"
    );
    assert_eq!(
        cert_chain["smtSiblings"].as_array().unwrap().len(),
        128,
        "smtSiblings length (smtDepth=128)"
    );
    assert_eq!(
        user_sig["tbs"].as_array().unwrap().len(),
        1536,
        "tbs length (maxMessageLength=1536)"
    );
    assert_eq!(
        user_sig["userPkLimbs"].as_array().unwrap().len(),
        17,
        "userPkLimbs length (kUser=17, always RSA-2048)"
    );
    assert_eq!(
        user_sig["userRsaSignature"].as_array().unwrap().len(),
        17,
        "userRsaSignature length (kUser=17)"
    );
}

#[test]
fn split_inputs_rs4096_share_pk_blind() {
    let (user_cert, user_sig_b64, issuer_cert, serial_hex) = load_rs4096_fixtures();

    let (cert_chain, user_sig) = generate_split_inputs(
        &user_cert,
        &issuer_cert,
        &user_sig_b64,
        DEFAULT_TBS,
        &serial_hex,
        None,
        34,
        17,
        MAX_CERT_CHAIN_LENGTH,
        TEST_PK_BLIND,
        DEFAULT_CHALLENGE,
        DEFAULT_CURRENT_TIME,
    )
    .expect("generate_split_inputs failed for RS4096");

    let cc_blind = cert_chain["pkBlind"].as_str().expect("cert_chain pkBlind not a string");
    let ds_blind = user_sig["pkBlind"].as_str().expect("user_sig pkBlind not a string");
    assert_eq!(
        cc_blind, ds_blind,
        "pkBlind must be identical across cert-chain and user-sig outputs (RS4096)"
    );
}

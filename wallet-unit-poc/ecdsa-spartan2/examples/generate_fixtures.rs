//! Deterministic synthetic test fixture generator.
//!
//! Overwrites `tests/testdata/response_sign_test.json` and
//! `tests/testdata/pkcs11info_test.json` (RS2048 path) and writes
//! `tests/testdata/rs4096_response_sign.json` and
//! `tests/testdata/test_ca_rs4096.der` (RS4096 path).
//!
//! All output is byte-stable for a given seed. The user cert's signature
//! covers `DEFAULT_TBS`, matching main.rs:139.
//!
//! Usage: `cargo run --example generate_fixtures`

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use der::Encode;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::Keypair as _;
use rsa::RsaPrivateKey;
use sha2::Sha256;
use std::time::Duration;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::asn1::{BitString, ObjectIdentifier, OctetString};
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, KeyUsage, KeyUsages, SubjectKeyIdentifier};
use x509_cert::ext::Extension;
use const_oid::db::rfc5280::{ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_KEY_USAGE, ID_CE_SUBJECT_KEY_IDENTIFIER};
use x509_cert::{TbsCertificate, Version};
use x509_cert::der::asn1::UtcTime;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};

use ecdsa_spartan2::DEFAULT_TBS;

// Change only to rotate synthetic keys.
const SEED_RS2048: [u8; 32] = [
    0x7a, 0x6b, 0x49, 0x44, 0x5f, 0x74, 0x65, 0x73,
    0x74, 0x5f, 0x66, 0x69, 0x78, 0x74, 0x75, 0x72,
    0x65, 0x73, 0x5f, 0x73, 0x65, 0x65, 0x64, 0x5f,
    0x76, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

const SEED_RS4096: [u8; 32] = [
    0x7a, 0x6b, 0x49, 0x44, 0x5f, 0x74, 0x65, 0x73,
    0x74, 0x5f, 0x66, 0x69, 0x78, 0x74, 0x75, 0x72,
    0x65, 0x73, 0x5f, 0x73, 0x65, 0x65, 0x64, 0x5f,
    0x76, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
];

const CA_SERIAL_HEX: &str = "26c76ee1317398df0a955d312f0645703a47418f";
const USER_SERIAL_HEX: &str = "5e4fad0a7c6dd854be121e7a00733b212c1aed8a";

const CA4096_SERIAL_HEX: &str = "3d8f12a04e7c6bb9c2d45810f3a72916b5e8340d";
const USER4096_SERIAL_HEX: &str = "7a1bc23d4ef56789abcde01234567890fedcba98";

// 2025-01-01 → 2034-12-30 (10 * 365 days, no leap adjustment — arbitrary window).
const NOT_BEFORE_UNIX: u64 = 1_735_689_600;
const VALIDITY_SECONDS: u64 = 10 * 365 * 24 * 3600;

const RESPONSE_SIGN_PATH: &str = "tests/testdata/response_sign_test.json";
const PKCS11INFO_PATH: &str = "tests/testdata/pkcs11info_test.json";
const RS4096_RESPONSE_SIGN_PATH: &str = "tests/testdata/rs4096_response_sign.json";
const TEST_CA_RS4096_DER_PATH: &str = "tests/testdata/test_ca_rs4096.der";

type BoxErr = Box<dyn std::error::Error>;

fn main() -> Result<(), BoxErr> {
    // Phase A: RS2048 fixtures (unchanged byte output)
    eprintln!("[1/2] generating RS2048 fixtures...");
    let ca2048_key = generate_rsa_key(SEED_RS2048, 0, 2048)?;
    let user2048_key = generate_rsa_key(SEED_RS2048, 1, 2048)?;
    let ca2048_cert = generate_ca_cert(&ca2048_key, CA_SERIAL_HEX)?;
    let user2048_cert = generate_user_cert(&user2048_key, &ca2048_key, &ca2048_cert, USER_SERIAL_HEX)?;
    let sig2048 = sign_test_challenge(&user2048_key)?;

    let ca2048_der = ca2048_cert.to_der()?;
    let user2048_der = user2048_cert.to_der()?;

    let response_tmp = format!("{}.tmp", RESPONSE_SIGN_PATH);
    let pkcs11_tmp = format!("{}.tmp", PKCS11INFO_PATH);
    write_response_sign(&response_tmp, &user2048_der, &sig2048)?;
    write_pkcs11info(&pkcs11_tmp, &ca2048_der, &user2048_der)?;

    // Phase B: RS4096 fixtures (slow — ~20s for 4096-bit keygen)
    eprintln!("[2/2] generating RS4096 fixtures (this takes ~20s)...");
    let ca4096_key = generate_rsa_key(SEED_RS4096, 0, 4096)?;
    let user4096_key = generate_rsa_key(SEED_RS4096, 1, 2048)?; // user stays 2048
    let ca4096_cert = generate_ca_cert(&ca4096_key, CA4096_SERIAL_HEX)?;
    let user4096_cert = generate_user_cert(&user4096_key, &ca4096_key, &ca4096_cert, USER4096_SERIAL_HEX)?;
    let sig4096 = sign_test_challenge(&user4096_key)?;

    let ca4096_der = ca4096_cert.to_der()?;
    let user4096_der = user4096_cert.to_der()?;

    let rs4096_resp_tmp = format!("{}.tmp", RS4096_RESPONSE_SIGN_PATH);
    let test_ca_tmp = format!("{}.tmp", TEST_CA_RS4096_DER_PATH);
    write_rs4096_response_sign(&rs4096_resp_tmp, &user4096_der, &sig4096)?;
    std::fs::write(&test_ca_tmp, &ca4096_der)?;

    // Commit all four files atomically
    std::fs::rename(&response_tmp, RESPONSE_SIGN_PATH)?;
    std::fs::rename(&pkcs11_tmp, PKCS11INFO_PATH)?;
    std::fs::rename(&rs4096_resp_tmp, RS4096_RESPONSE_SIGN_PATH)?;
    std::fs::rename(&test_ca_tmp, TEST_CA_RS4096_DER_PATH)?;

    eprintln!("fixtures written:");
    eprintln!("  {RESPONSE_SIGN_PATH}");
    eprintln!("  {PKCS11INFO_PATH}");
    eprintln!("  {RS4096_RESPONSE_SIGN_PATH}");
    eprintln!("  {TEST_CA_RS4096_DER_PATH}");
    Ok(())
}

fn generate_rsa_key(seed: [u8; 32], index: u8, bits: usize) -> Result<RsaPrivateKey, BoxErr> {
    let mut s = seed;
    s[31] ^= index;
    let mut rng = ChaCha20Rng::from_seed(s);
    Ok(RsaPrivateKey::new(&mut rng, bits)?)
}

fn fixed_validity() -> Result<Validity, BoxErr> {
    let not_before = Time::UtcTime(UtcTime::from_unix_duration(
        Duration::from_secs(NOT_BEFORE_UNIX),
    )?);
    let not_after = Time::UtcTime(UtcTime::from_unix_duration(
        Duration::from_secs(NOT_BEFORE_UNIX + VALIDITY_SECONDS),
    )?);
    Ok(Validity { not_before, not_after })
}

fn generate_ca_cert(ca_key: &RsaPrivateKey, serial_hex: &str) -> Result<x509_cert::Certificate, BoxErr> {
    let serial = SerialNumber::new(&hex::decode(serial_hex)?)?;
    let subject: Name =
        "C=TW,O=Test Government CA,OU=Test Certificate Authority".parse()?;
    let signer = SigningKey::<Sha256>::new(ca_key.clone());
    let spki = SubjectPublicKeyInfoOwned::from_key(signer.verifying_key())?;

    let builder = CertificateBuilder::new(
        Profile::Root,
        serial,
        fixed_validity()?,
        subject,
        spki,
        &signer,
    )?;

    Ok(builder.build::<rsa::pkcs1v15::Signature>()?)
}

/// Builds the user certificate by hand rather than through
/// `CertificateBuilder`, so the extensions follow the order of a real MOICA
/// end-entity certificate: authorityKeyIdentifier, subjectKeyIdentifier,
/// keyUsage (critical, digitalSignature only), then the rest. The cert-chain
/// circuit walks to keyUsage structurally and rejects any other layout.
fn generate_user_cert(
    user_key: &RsaPrivateKey,
    ca_key: &RsaPrivateKey,
    ca_cert: &x509_cert::Certificate,
    serial_hex: &str,
) -> Result<x509_cert::Certificate, BoxErr> {
    use rsa::signature::{SignatureEncoding as _, Signer as _};

    let serial = SerialNumber::new(&hex::decode(serial_hex)?)?;
    let subject: Name = "C=TW,CN=Test User,serialNumber=0000000000000000".parse()?;

    let ca_signer = SigningKey::<Sha256>::new(ca_key.clone());
    let user_signer = SigningKey::<Sha256>::new(user_key.clone());
    let user_spki = SubjectPublicKeyInfoOwned::from_key(user_signer.verifying_key())?;

    let authority_key_id = key_identifier(&ca_cert.tbs_certificate.subject_public_key_info)?;
    let subject_key_id = key_identifier(&user_spki)?;

    let extensions = vec![
        extension(
            ID_CE_AUTHORITY_KEY_IDENTIFIER,
            false,
            &AuthorityKeyIdentifier {
                key_identifier: Some(OctetString::new(authority_key_id)?),
                authority_cert_issuer: None,
                authority_cert_serial_number: None,
            },
        )?,
        extension(
            ID_CE_SUBJECT_KEY_IDENTIFIER,
            false,
            &SubjectKeyIdentifier(OctetString::new(subject_key_id)?),
        )?,
        extension(
            ID_CE_KEY_USAGE,
            true,
            &KeyUsage(KeyUsages::DigitalSignature.into()),
        )?,
        // Stands in for the certificatePolicies, subjectDirectoryAttributes,
        // cRLDistributionPoints and authorityInfoAccess extensions of a real
        // certificate. Those run to several hundred bytes, which puts the
        // Extensions length in the two-byte long form the circuit expects.
        Extension {
            extn_id: ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1"),
            critical: false,
            extn_value: OctetString::new(vec![0xcc; 240])?,
        },
    ];

    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: serial,
        signature: ca_cert.signature_algorithm.clone(),
        issuer: ca_cert.tbs_certificate.subject.clone(),
        validity: fixed_validity()?,
        subject,
        subject_public_key_info: user_spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };

    let signature: rsa::pkcs1v15::Signature = ca_signer.try_sign(&tbs.to_der()?)?;
    Ok(x509_cert::Certificate {
        tbs_certificate: tbs,
        signature_algorithm: ca_cert.signature_algorithm.clone(),
        signature: BitString::from_bytes(&signature.to_vec())?,
    })
}

fn extension<T: Encode>(oid: ObjectIdentifier, critical: bool, value: &T) -> Result<Extension, BoxErr> {
    Ok(Extension {
        extn_id: oid,
        critical,
        extn_value: OctetString::new(value.to_der()?)?,
    })
}

/// 20-byte key identifier: the leading bytes of SHA-256 over the public key.
fn key_identifier(spki: &SubjectPublicKeyInfoOwned) -> Result<Vec<u8>, BoxErr> {
    use sha2::Digest as _;
    let digest = Sha256::digest(spki.subject_public_key.raw_bytes());
    Ok(digest[..20].to_vec())
}

fn sign_test_challenge(user_key: &RsaPrivateKey) -> Result<Vec<u8>, BoxErr> {
    use rsa::signature::{SignatureEncoding as _, Signer as _};
    let signer = SigningKey::<Sha256>::new(user_key.clone());
    let sig: rsa::pkcs1v15::Signature = signer.try_sign(DEFAULT_TBS)?;
    Ok(sig.to_vec())
}

fn write_response_sign(path: &str, user_der: &[u8], sig_bytes: &[u8]) -> Result<(), BoxErr> {
    let payload = serde_json::json!({
        "cardSN":     "TEST000000000000",
        "certb64":    B64.encode(user_der),
        "func":       "sign",
        "last_error": 0,
        "ret_code":   0,
        "signature":  B64.encode(sig_bytes),
        "version":    "0.0.0"
    });
    std::fs::write(path, serde_json::to_string_pretty(&payload)?)?;
    Ok(())
}

fn write_pkcs11info(path: &str, ca_der: &[u8], user_der: &[u8]) -> Result<(), BoxErr> {
    let payload = serde_json::json!({
        "func":       "pkcs11info",
        "last_error": 0,
        "ret_code":   0,
        "slots": [{
            "token": {
                "certs": [
                    {
                        "certb64":   B64.encode(ca_der),
                        "label":     "CA Cert",
                        "subjectDN": "C=TW,O=Test Government CA,OU=Test Certificate Authority",
                        "issuerDN":  "C=TW,O=Test Government CA,OU=Test Certificate Authority",
                        "usage":     "keyCertSign|cRLSign"
                    },
                    {
                        "certb64":   B64.encode(user_der),
                        "label":     "cert1",
                        "subjectDN": "C=TW,CN=Test User,serialNumber=0000000000000000",
                        "issuerDN":  "C=TW,O=Test Government CA,OU=Test Certificate Authority",
                        "usage":     "digitalSignature"
                    }
                ]
            }
        }]
    });
    std::fs::write(path, serde_json::to_string_pretty(&payload)?)?;
    Ok(())
}

fn write_rs4096_response_sign(path: &str, user_der: &[u8], sig_bytes: &[u8]) -> Result<(), BoxErr> {
    let payload = serde_json::json!({
        "error_code": "000",
        "error_message": "success",
        "result": {
            "hashed_id_num":   "0000000000000000000000000000000000000000000000000000000000000000",
            "signed_response": B64.encode(sig_bytes),
            "idp_checksum":    "00000000",
            "cert":            B64.encode(user_der)
        }
    });
    std::fs::write(path, serde_json::to_string_pretty(&payload)?)?;
    Ok(())
}

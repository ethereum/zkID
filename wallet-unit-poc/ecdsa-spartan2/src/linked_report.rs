//! Linked Prepare + Show verification with a machine-readable report, for
//! `jsonld verify-linked --json`.

use std::path::Path;

use num_bigint::{BigInt, Sign};
use ff::PrimeField;
use serde_json::{json, Map, Value};
use spartan2::traits::snark::R1CSSNARKTrait;

use crate::{
    setup::{load_proof, load_verifying_key},
    utils::{
        calculate_jsonld_output_indices, SHOW_MAX_LOGIC_TOKENS, SHOW_MAX_PREDICATES,
        SHOW_NAME_ID_LEN, SHOW_NUM_PUBLIC,
    },
    Scalar,
};

/// Outcome of verifying a Prepare + Show pair. `None` public values mean the
/// proof or key failed to load, or the proof did not verify.
#[derive(Debug, Clone)]
pub struct LinkedVerification {
    pub prepare_public: Option<Vec<Scalar>>,
    pub show_public: Option<Vec<Scalar>>,
    pub comm_w_shared_equal: bool,
    /// Hex of the bincode-serialized `comm_W_shared` carried by each proof;
    /// `None` when the proof failed to load or has no shared commitment.
    pub prepare_comm: Option<String>,
    pub show_comm: Option<String>,
}

fn comm_hex(proof: &Option<spartan2::zk_spartan::R1CSSNARK<crate::E>>) -> Option<String> {
    let comm = proof.as_ref()?.comm_W_shared().as_ref()?;
    let bytes = bincode::serialize(comm).ok()?;
    Some(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Unlike `prover::verify_linked`, reports each check separately instead of
/// collapsing them into one `Option`.
pub fn verify_linked_detailed(
    prepare_proof_path: impl AsRef<Path>,
    prepare_vk_path: impl AsRef<Path>,
    show_proof_path: impl AsRef<Path>,
    show_vk_path: impl AsRef<Path>,
) -> LinkedVerification {
    let prepare_proof = load_proof(&prepare_proof_path).ok();
    let show_proof = load_proof(&show_proof_path).ok();
    let prepare_vk = load_verifying_key(&prepare_vk_path).ok();
    let show_vk = load_verifying_key(&show_vk_path).ok();

    let prepare_public = prepare_proof
        .as_ref()
        .zip(prepare_vk.as_ref())
        .and_then(|(p, vk)| p.verify(vk).ok());
    let show_public = show_proof
        .as_ref()
        .zip(show_vk.as_ref())
        .and_then(|(p, vk)| p.verify(vk).ok());

    // Read from the proofs themselves, never from a caller-supplied instance.
    let comm_w_shared_equal = match (&prepare_proof, &show_proof) {
        (Some(p), Some(s)) => {
            let (p, s) = (p.comm_W_shared(), s.comm_W_shared());
            p.is_some() && p == s
        }
        _ => false,
    };

    LinkedVerification {
        prepare_public,
        show_public,
        comm_w_shared_equal,
        prepare_comm: comm_hex(&prepare_proof),
        show_comm: comm_hex(&show_proof),
    }
}

pub fn scalar_to_decimal(s: &Scalar) -> String {
    // `PrimeField::to_repr` is little-endian for the derived field types.
    BigInt::from_bytes_le(Sign::Plus, s.to_repr().as_ref()).to_string()
}

enum Shape {
    Single,
    Array(usize),
    Matrix(usize, usize),
}

/// Show public signals in witness order: the `expressionResult` output, then
/// the public inputs in template declaration order (see [`SHOW_NUM_PUBLIC`]).
fn show_public_fields() -> [(&'static str, Shape); 14] {
    use Shape::*;
    let p = SHOW_MAX_PREDICATES;
    let t = SHOW_MAX_LOGIC_TOKENS;
    [
        ("expressionResult", Single),
        ("messageHash", Single),
        ("predicateLen", Single),
        ("predicateClaimRefs", Array(p)),
        ("predicateOps", Array(p)),
        ("predicateRhsIsRef", Array(p)),
        ("predicateRhsValues", Array(p)),
        ("predicateClaimNames", Matrix(p, SHOW_NAME_ID_LEN)),
        ("predicateClaimNameLens", Array(p)),
        ("predicateRhsClaimNames", Matrix(p, SHOW_NAME_ID_LEN)),
        ("predicateRhsClaimNameLens", Array(p)),
        ("tokenTypes", Array(t)),
        ("tokenValues", Array(t)),
        ("exprLen", Single),
    ]
}

fn decimals(values: &[Scalar]) -> Vec<String> {
    values.iter().map(scalar_to_decimal).collect()
}

/// Show public values keyed by circuits.json name, plus `expressionResult`.
/// `None` when the vector does not have the layout this binary expects.
pub fn show_public_json(values: &[Scalar]) -> Option<Value> {
    if values.len() != SHOW_NUM_PUBLIC {
        return None;
    }
    let mut out = Map::new();
    let mut rest = values;
    let mut take = |n: usize| {
        let (head, tail) = rest.split_at(n);
        rest = tail;
        head
    };
    for (name, shape) in show_public_fields() {
        let entry = match shape {
            Shape::Single => json!(scalar_to_decimal(&take(1)[0])),
            Shape::Array(n) => json!(decimals(take(n))),
            Shape::Matrix(rows, cols) => {
                let rows: Vec<Vec<String>> = take(rows * cols).chunks(cols).map(decimals).collect();
                json!(rows)
            }
        };
        out.insert(name.to_string(), entry);
    }
    Some(Value::Object(out))
}

/// Prepare public values for the JSON-LD circuit. `None` on a layout mismatch.
pub fn jsonld_public_json(values: &[Scalar], max_claims: usize) -> Option<Value> {
    let layout = calculate_jsonld_output_indices(max_claims);
    if values.len() != layout.num_public() {
        return None;
    }
    // `values[i]` is `witness[i + 1]`.
    let at = |idx: usize| &values[idx - 1];
    let slice = |r: std::ops::Range<usize>| decimals(&values[r.start - 1..r.end - 1]);
    Some(json!({
        "pubKeyX": scalar_to_decimal(at(layout.issuer_key_x_index)),
        "pubKeyY": scalar_to_decimal(at(layout.issuer_key_y_index)),
        "claimFormats": slice(layout.claim_formats_range()),
        "claimFlags": slice(layout.claim_flags_range()),
    }))
}

/// Values the caller requires the proofs to expose, as canonical decimal strings.
/// A `None` field is not checked and is reported as `null`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Expectations {
    pub issuer_key: Option<(String, String)>,
    pub message_hash: Option<String>,
}

/// Canonicalize a decimal integer so `"007"` and `"7"` compare equal.
pub fn canonical_decimal(s: &str) -> Result<String, String> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("'{s}' is not a non-negative decimal integer"));
    }
    s.parse::<BigInt>()
        .map(|n| n.to_string())
        .map_err(|e| e.to_string())
}

/// Build the `verify-linked --json` object. The bool is true only when both
/// proofs verified, their public values parsed, `comm_W_shared` matched, Show's
/// `expressionResult` is 1, and every supplied expectation matched.
/// Public values of a proof that did not verify are reported as `null`.
pub fn build_report(
    result: &LinkedVerification,
    max_claims: usize,
    expect: &Expectations,
) -> (Value, bool) {
    let prepare_public = result
        .prepare_public
        .as_deref()
        .and_then(|v| jsonld_public_json(v, max_claims));
    let show_public = result.show_public.as_deref().and_then(show_public_json);

    let prepare_valid = prepare_public.is_some();
    let show_valid = show_public.is_some();

    let show_str = |name: &str| show_public.as_ref().and_then(|s| s[name].as_str());
    let expression_result = show_str("expressionResult") == Some("1");

    let issuer_key_matches = expect.issuer_key.as_ref().map(|(x, y)| {
        prepare_public.as_ref().is_some_and(|p| {
            p["pubKeyX"].as_str() == Some(x.as_str()) && p["pubKeyY"].as_str() == Some(y.as_str())
        })
    });
    let message_hash_matches = expect
        .message_hash
        .as_ref()
        .map(|h| show_str("messageHash") == Some(h.as_str()));

    let ok = prepare_valid
        && show_valid
        && result.comm_w_shared_equal
        && expression_result
        && issuer_key_matches != Some(false)
        && message_hash_matches != Some(false);

    let report = json!({
        "prepareValid": prepare_valid,
        "showValid": show_valid,
        "commWSharedEqual": result.comm_w_shared_equal,
        "commWShared": result.prepare_comm,
        "commWSharedShow": result.show_comm,
        "expressionResult": expression_result,
        "issuerKeyMatches": issuer_key_matches,
        "messageHashMatches": message_hash_matches,
        "preparePublic": prepare_public,
        "showPublic": show_public,
    });
    (report, ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalars(n: usize) -> Vec<Scalar> {
        (1..=n as u64).map(Scalar::from).collect()
    }

    #[test]
    fn scalar_decimal_is_little_endian_repr() {
        assert_eq!(scalar_to_decimal(&Scalar::from(42u64)), "42");
        assert_eq!(scalar_to_decimal(&Scalar::from(0u64)), "0");
        assert_eq!(
            scalar_to_decimal(&Scalar::from(u64::MAX)),
            u64::MAX.to_string()
        );
    }

    #[test]
    fn show_fields_cover_the_public_prefix_exactly() {
        let total: usize = show_public_fields()
            .iter()
            .map(|(_, s)| match s {
                Shape::Single => 1,
                Shape::Array(n) => *n,
                Shape::Matrix(r, c) => r * c,
            })
            .sum();
        assert_eq!(total, SHOW_NUM_PUBLIC);
    }

    #[test]
    fn show_json_names_every_public_input() {
        let json = show_public_json(&scalars(SHOW_NUM_PUBLIC)).unwrap();
        let obj = json.as_object().unwrap();
        for name in [
            "expressionResult", "messageHash", "predicateLen", "predicateClaimRefs",
            "predicateOps", "predicateRhsIsRef", "predicateRhsValues", "tokenTypes",
            "tokenValues", "exprLen", "predicateClaimNames", "predicateClaimNameLens",
            "predicateRhsClaimNames", "predicateRhsClaimNameLens",
        ] {
            assert!(obj.contains_key(name), "missing {name}");
        }
        assert_eq!(obj["expressionResult"], json!("1"));
        assert_eq!(obj["messageHash"], json!("2"));
        assert_eq!(obj["predicateClaimRefs"], json!(["4", "5"]));
        assert_eq!(obj["predicateClaimNames"][1].as_array().unwrap().len(), SHOW_NAME_ID_LEN);
        assert_eq!(obj["exprLen"], json!(SHOW_NUM_PUBLIC.to_string()));
        assert!(show_public_json(&scalars(SHOW_NUM_PUBLIC - 1)).is_none());
    }

    #[test]
    fn prepare_json_follows_layout() {
        let json = jsonld_public_json(&scalars(10), 4).unwrap();
        assert_eq!(json["pubKeyX"], json!("1"));
        assert_eq!(json["pubKeyY"], json!("2"));
        assert_eq!(json["claimFormats"], json!(["3", "4", "5", "6"]));
        assert_eq!(json["claimFlags"], json!(["7", "8", "9", "10"]));
        assert!(jsonld_public_json(&scalars(9), 4).is_none());
    }

    fn good() -> LinkedVerification {
        LinkedVerification {
            prepare_public: Some(scalars(10)),
            show_public: Some(scalars(SHOW_NUM_PUBLIC)),
            comm_w_shared_equal: true,
            prepare_comm: Some("ab01".into()),
            show_comm: Some("ab01".into()),
        }
    }

    fn none() -> Expectations {
        Expectations::default()
    }

    #[test]
    fn report_has_the_documented_shape() {
        let (report, ok) = build_report(&good(), 4, &none());
        assert!(ok);
        assert_eq!(report["prepareValid"], json!(true));
        assert_eq!(report["showValid"], json!(true));
        assert_eq!(report["commWSharedEqual"], json!(true));
        assert_eq!(report["expressionResult"], json!(true));
        assert_eq!(report["commWShared"], json!("ab01"));
        assert_eq!(report["commWSharedShow"], json!("ab01"));
        assert!(report["issuerKeyMatches"].is_null());
        assert!(report["messageHashMatches"].is_null());
        assert!(report["preparePublic"]["claimFlags"].is_array());
        assert!(report["showPublic"]["expressionResult"].is_string());
    }

    #[test]
    fn any_failed_check_fails_the_report() {
        let mut r = good();
        r.comm_w_shared_equal = false;
        assert!(!build_report(&r, 4, &none()).1);

        let mut r = good();
        r.prepare_public = None;
        let (report, ok) = build_report(&r, 4, &none());
        assert!(!ok);
        assert_eq!(report["prepareValid"], json!(false));
        assert!(report["preparePublic"].is_null());

        let mut r = good();
        r.show_public = Some(scalars(3));
        assert!(!build_report(&r, 4, &none()).1);
    }

    #[test]
    fn false_expression_result_fails_the_exit_decision() {
        let mut r = good();
        // Both proofs verify; the predicate simply evaluated to false.
        r.show_public.as_mut().unwrap()[0] = Scalar::from(0u64);
        let (report, ok) = build_report(&r, 4, &none());
        assert!(!ok);
        assert_eq!(report["showValid"], json!(true));
        assert_eq!(report["expressionResult"], json!(false));
    }

    #[test]
    fn expectations_gate_the_exit_decision() {
        // good(): pubKeyX=1, pubKeyY=2, messageHash=2.
        let issuer = |x: &str, y: &str| Expectations {
            issuer_key: Some((x.into(), y.into())),
            message_hash: None,
        };
        let hash = |h: &str| Expectations {
            issuer_key: None,
            message_hash: Some(h.into()),
        };

        let (report, ok) = build_report(&good(), 4, &issuer("1", "2"));
        assert!(ok);
        assert_eq!(report["issuerKeyMatches"], json!(true));

        for bad in [issuer("9", "2"), issuer("1", "9")] {
            let (report, ok) = build_report(&good(), 4, &bad);
            assert!(!ok);
            assert_eq!(report["issuerKeyMatches"], json!(false));
        }

        let (report, ok) = build_report(&good(), 4, &hash("2"));
        assert!(ok);
        assert_eq!(report["messageHashMatches"], json!(true));

        let (report, ok) = build_report(&good(), 4, &hash("3"));
        assert!(!ok);
        assert_eq!(report["messageHashMatches"], json!(false));

        let all = Expectations {
            issuer_key: Some(("1".into(), "2".into())),
            message_hash: Some("2".into()),
        };
        assert!(build_report(&good(), 4, &all).1);
    }

    #[test]
    fn expectation_against_an_unverified_proof_is_a_mismatch() {
        let mut r = good();
        r.prepare_public = None;
        let e = Expectations {
            issuer_key: Some(("1".into(), "2".into())),
            message_hash: None,
        };
        let (report, ok) = build_report(&r, 4, &e);
        assert!(!ok);
        assert_eq!(report["issuerKeyMatches"], json!(false));
    }

    #[test]
    fn canonical_decimal_normalizes_and_rejects() {
        assert_eq!(canonical_decimal("007").unwrap(), "7");
        assert_eq!(canonical_decimal("0").unwrap(), "0");
        for bad in ["", "-1", "0x10", "1.5", " 1"] {
            assert!(canonical_decimal(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn missing_files_report_everything_false() {
        let r = verify_linked_detailed("/nonexistent/a", "/nonexistent/b", "/nonexistent/c", "/nonexistent/d");
        let (report, ok) = build_report(&r, 4, &none());
        assert!(!ok);
        assert_eq!(report["commWSharedEqual"], json!(false));
        assert!(report["commWShared"].is_null());
        assert!(report["commWSharedShow"].is_null());
        assert_eq!(report["showValid"], json!(false));
    }
}

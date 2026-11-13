use ecdsa_spartan2::{bigint_to_scalar, utils::SHOW_NUM_PUBLIC, Scalar};
use ff::{Field, PrimeField};
use num_bigint::{BigInt, Sign};

/// Prepare public values start with the issuer key (x, y); the rest is the
/// per-claim decode flags and formats ("normalization").
const ISSUER_KEY_LEN: usize = 2;

/// Show public values: `[0]` expressionResult, `[1]` nonce hash, `[2..]` policy.
const SHOW_BOUND_LEN: usize = SHOW_NUM_PUBLIC - 1;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct StatementCheck {
    pub issuer_trusted: bool,
    pub normalization_matches: bool,
    pub nonce_matches: bool,
    pub policy_matches: bool,
    pub expression_result: bool,
    pub failure: Option<String>,
}

pub fn parse_decimal_scalars(values: &[String]) -> Result<Vec<Scalar>, String> {
    values
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let n = BigInt::parse_bytes(s.trim().as_bytes(), 10)
                .filter(|n| n.sign() != Sign::Minus)
                .ok_or_else(|| format!("value {i} is not a non-negative decimal integer"))?;
            bigint_to_scalar(n).map_err(|_| format!("value {i} is not a valid field element"))
        })
        .collect()
}

pub fn scalar_to_decimal(s: &Scalar) -> String {
    BigInt::from_bytes_le(Sign::Plus, s.to_repr().as_ref()).to_string()
}

/// `expected_show` is `show_pv[1..]`: the nonce hash, then the policy.
pub fn check_statement(
    prepare_pv: &[Scalar],
    show_pv: &[Scalar],
    expected_prepare: &[Scalar],
    expected_show: &[Scalar],
) -> StatementCheck {
    let mut check = StatementCheck {
        expression_result: show_pv.first() == Some(&Scalar::ONE),
        ..Default::default()
    };

    let prepare_len_ok = prepare_pv.len() >= ISSUER_KEY_LEN + 2
        && prepare_pv.len() % 2 == 0
        && prepare_pv.len() == expected_prepare.len();
    if !prepare_len_ok {
        check.failure = Some(format!(
            "prepare public values have length {}, expected {}",
            prepare_pv.len(),
            expected_prepare.len()
        ));
        return check;
    }
    if show_pv.len() != SHOW_NUM_PUBLIC || expected_show.len() != SHOW_BOUND_LEN {
        check.failure = Some(format!(
            "show public values have length {} (expected statement {}), want {} (statement {})",
            show_pv.len(),
            expected_show.len(),
            SHOW_NUM_PUBLIC,
            SHOW_BOUND_LEN
        ));
        return check;
    }

    check.issuer_trusted = prepare_pv[..ISSUER_KEY_LEN] == expected_prepare[..ISSUER_KEY_LEN];
    check.normalization_matches = prepare_pv[ISSUER_KEY_LEN..] == expected_prepare[ISSUER_KEY_LEN..];
    check.nonce_matches = show_pv[1] == expected_show[0];
    check.policy_matches = show_pv[2..] == expected_show[1..];

    check.failure = if !check.issuer_trusted {
        Some("issuer not trusted".into())
    } else if !check.normalization_matches {
        Some("claim normalization mismatch".into())
    } else if !check.nonce_matches {
        Some("nonce mismatch".into())
    } else if !check.policy_matches {
        Some("policy mismatch".into())
    } else {
        None
    };
    check
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(n: u64) -> Scalar {
        Scalar::from(n)
    }

    fn prepare() -> Vec<Scalar> {
        vec![s(11), s(12), s(1), s(2), s(3), s(4)]
    }

    fn show() -> Vec<Scalar> {
        let mut v = vec![s(1), s(777)];
        v.extend((0..SHOW_NUM_PUBLIC - 2).map(|i| s(i as u64 + 100)));
        v
    }

    fn expected_show() -> Vec<Scalar> {
        show()[1..].to_vec()
    }

    #[test]
    fn show_public_count_matches_layout() {
        let layout = ecdsa_spartan2::utils::calculate_show_witness_indices(2);
        assert_eq!(layout.num_public(), 156);
        assert_eq!(SHOW_NUM_PUBLIC, layout.num_public());
    }

    #[test]
    fn all_match() {
        let c = check_statement(&prepare(), &show(), &prepare(), &expected_show());
        assert_eq!(
            c,
            StatementCheck {
                issuer_trusted: true,
                normalization_matches: true,
                nonce_matches: true,
                policy_matches: true,
                expression_result: true,
                failure: None,
            }
        );
    }

    #[test]
    fn issuer_mismatch_only() {
        let mut exp = prepare();
        exp[1] = s(99);
        let c = check_statement(&prepare(), &show(), &exp, &expected_show());
        assert!(!c.issuer_trusted);
        assert!(c.normalization_matches && c.nonce_matches && c.policy_matches);
        assert_eq!(c.failure.as_deref(), Some("issuer not trusted"));
    }

    #[test]
    fn normalization_mismatch_only() {
        let mut exp = prepare();
        exp[5] = s(99);
        let c = check_statement(&prepare(), &show(), &exp, &expected_show());
        assert!(!c.normalization_matches);
        assert!(c.issuer_trusted && c.nonce_matches && c.policy_matches);
        assert_eq!(c.failure.as_deref(), Some("claim normalization mismatch"));
    }

    #[test]
    fn nonce_mismatch_only() {
        let mut exp = expected_show();
        exp[0] = s(1);
        let c = check_statement(&prepare(), &show(), &prepare(), &exp);
        assert!(!c.nonce_matches);
        assert!(c.issuer_trusted && c.normalization_matches && c.policy_matches);
        assert_eq!(c.failure.as_deref(), Some("nonce mismatch"));
    }

    #[test]
    fn policy_mismatch_only() {
        let mut exp = expected_show();
        *exp.last_mut().unwrap() = s(1);
        let c = check_statement(&prepare(), &show(), &prepare(), &exp);
        assert!(!c.policy_matches);
        assert!(c.issuer_trusted && c.normalization_matches && c.nonce_matches);
        assert_eq!(c.failure.as_deref(), Some("policy mismatch"));
    }

    #[test]
    fn expression_result_is_one_only_for_one() {
        let mut v = show();
        v[0] = s(0);
        let c = check_statement(&prepare(), &v, &prepare(), &expected_show());
        assert!(!c.expression_result);
        assert!(c.failure.is_none());
        v[0] = s(2);
        let c = check_statement(&prepare(), &v, &prepare(), &expected_show());
        assert!(!c.expression_result);
    }

    #[test]
    fn expression_result_reported_when_invalid() {
        let mut exp = expected_show();
        exp[0] = s(1);
        let c = check_statement(&prepare(), &show(), &prepare(), &exp);
        assert!(c.expression_result);
        assert!(c.failure.is_some());
    }

    #[test]
    fn bad_prepare_lengths_fail_without_panic() {
        for bad in [vec![], vec![s(1)], prepare()[..5].to_vec(), prepare()[..4].to_vec()] {
            let c = check_statement(&bad, &show(), &prepare(), &expected_show());
            assert!(c.failure.is_some());
            assert!(!c.issuer_trusted && !c.normalization_matches);
        }
        let c = check_statement(&prepare(), &show(), &prepare()[..4], &expected_show());
        assert!(c.failure.is_some());
    }

    #[test]
    fn bad_show_lengths_fail_without_panic() {
        let short = show()[..10].to_vec();
        let c = check_statement(&prepare(), &short, &prepare(), &expected_show());
        assert!(c.failure.is_some());
        assert!(!c.nonce_matches && !c.policy_matches);

        let c = check_statement(&prepare(), &[], &prepare(), &expected_show());
        assert!(c.failure.is_some());
        assert!(!c.expression_result);

        let c = check_statement(&prepare(), &show(), &prepare(), &expected_show()[..3]);
        assert!(c.failure.is_some());

        let mut long = show();
        long.push(s(1));
        let c = check_statement(&prepare(), &long, &prepare(), &expected_show());
        assert!(c.failure.is_some());
    }

    #[test]
    fn parses_decimal_scalars() {
        let parsed = parse_decimal_scalars(&["0".into(), " 42 ".into(), "255".into()]).unwrap();
        assert_eq!(parsed, vec![s(0), s(42), s(255)]);
        assert_eq!(parse_decimal_scalars(&[]).unwrap(), vec![]);
    }

    #[test]
    fn rejects_invalid_scalars() {
        for bad in ["", "abc", "0x10", "-1", "1.5", "12 3"] {
            let err = parse_decimal_scalars(&["1".into(), bad.into()]).unwrap_err();
            assert!(err.contains("value 1"), "{bad}: {err}");
        }
        // 2^256 does not fit in 32 bytes; the field modulus itself is not canonical.
        let too_big: BigInt = BigInt::from(1u8) << 256usize;
        assert!(parse_decimal_scalars(&[too_big.to_string()]).is_err());
        let modulus = "115792089210356248762697446949407573530086143415290314195533631308867097853951";
        assert!(parse_decimal_scalars(&[modulus.into()]).is_err());
    }

    #[test]
    fn decimal_round_trip() {
        let n = "123456789012345678901234567890";
        let parsed = parse_decimal_scalars(&[n.into()]).unwrap();
        assert_eq!(scalar_to_decimal(&parsed[0]), n);
    }
}

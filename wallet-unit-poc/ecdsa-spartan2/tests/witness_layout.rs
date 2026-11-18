//! Re-derive the hardcoded witness offsets from the circuits' `.sym` files.
//!
//! `normalizedClaimValues` are private signals, so their witness positions are
//! assigned by the Circom compiler rather than fixed by the template parameters,
//! and they shift whenever the circuit changes. The offsets are hardcoded (in
//! `CircuitSize::claim_values_witness_start` and `MDOC_CLAIM_VALUES_WITNESS_START`)
//! because reading a ~200 MB `.sym` at runtime is not viable — these tests are
//! what keep the constants honest.
//!
//! Skipped when a circuit has not been compiled.

use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
};

use ecdsa_spartan2::{
    circuit_size::CircuitSize,
    utils::{
        calculate_jwt_output_indices, calculate_mdoc_output_indices,
        calculate_show_witness_indices, MDOC_CLAIM_IDENTIFIER_HASHES_WITNESS_START,
        MDOC_CLAIM_VALUES_WITNESS_START,
    },
};

const MDOC_MAX_CLAIMS: usize = 4;

fn sym_path(circuit: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("circom/build")
        .join(circuit)
        .join(format!("{circuit}.sym"))
}

/// Map `main.<name>` to its witness index, for the signals named in `wanted`.
///
/// `.sym` lines are `symbol_index,witness_index,node_id,name`; a witness index
/// of `-1` means the optimizer removed the signal. Stops as soon as every
/// requested signal is found, so it reads only the `main.*` prefix rather than
/// the whole file.
fn witness_indices(circuit: &str, wanted: &[String]) -> Option<Vec<usize>> {
    let file = File::open(sym_path(circuit)).ok()?;
    let mut found: Vec<Option<usize>> = vec![None; wanted.len()];

    for line in BufReader::new(file).lines().map_while(Result::ok) {
        let mut parts = line.splitn(4, ',');
        let (_, w_idx, _, name) = match (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) {
            (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
            _ => continue,
        };

        if let Some(slot) = wanted.iter().position(|w| w == name) {
            let idx: i64 = w_idx.parse().ok()?;
            assert!(
                idx >= 0,
                "{circuit}: {name} was optimized out of the witness (index -1); \
                 the shared-witness binding cannot read it"
            );
            found[slot] = Some(idx as usize);
            if found.iter().all(Option::is_some) {
                break;
            }
        }
    }

    found.into_iter().collect()
}

#[test]
fn jwt_claim_value_offsets_match_sym() {
    let mut checked = 0;

    for size in CircuitSize::ALL {
        let layout = calculate_jwt_output_indices(size);
        let wanted: Vec<String> = (0..layout.claim_values_len)
            .map(|i| format!("main.normalizedClaimValues[{i}]"))
            .chain(["main.KeyBindingX".into(), "main.KeyBindingY".into()])
            .collect();

        let Some(actual) = witness_indices(size.circuit_name(), &wanted) else {
            eprintln!("skipping {size}: circuit not compiled");
            continue;
        };
        checked += 1;

        let expected: Vec<usize> = layout
            .claim_values_range()
            .chain([layout.keybinding_x_index, layout.keybinding_y_index])
            .collect();

        assert_eq!(
            actual, expected,
            "{size}: witness layout drifted from the compiled circuit. \
             Recompile happened without updating \
             CircuitSize::claim_values_witness_start (and the matching \
             CLAIM_VALUES_WITNESS_START in openac-sdk/src/sizing.ts)."
        );

        // The two leaks this change exists to close. The circuit publishes the
        // issuer key and the normalization flags (2n + 2 public inputs, no public
        // outputs), but never claim values -- which would reveal the exact
        // attribute -- nor the device key, a constant identifier that survives
        // reblinding and lets a verifier recognize a returning holder.
        assert_eq!(
            layout.num_public(),
            2 * layout.claim_values_len + 2,
            "{size}: JWT public IO must be exactly issuer key + decodeFlags + claimFormats"
        );
        for idx in layout
            .claim_values_range()
            .chain([layout.keybinding_x_index, layout.keybinding_y_index])
        {
            assert!(
                idx > layout.num_public(),
                "{size}: witness[{idx}] is inside the public IO"
            );
        }
    }

    assert!(checked > 0, "no JWT circuits compiled; nothing verified");
}

#[test]
fn mdoc_claim_value_offsets_match_sym() {
    let layout = calculate_mdoc_output_indices(MDOC_MAX_CLAIMS);
    let wanted: Vec<String> = (0..MDOC_MAX_CLAIMS)
        .map(|i| format!("main.normalizedClaimValues[{i}]"))
        .chain((0..MDOC_MAX_CLAIMS).map(|i| format!("main.claimIdentifierHashes[{i}]")))
        .chain([
            "main.validUntilDate".into(),
            "main.deviceKeyX".into(),
            "main.deviceKeyY".into(),
        ])
        .collect();

    let Some(actual) = witness_indices("mdoc", &wanted) else {
        eprintln!("skipping mdoc: circuit not compiled");
        return;
    };

    let expected: Vec<usize> = layout
        .claim_values_range()
        .chain(
            layout.claim_identifier_hashes_start
                ..layout.claim_identifier_hashes_start + MDOC_MAX_CLAIMS,
        )
        .chain([
            layout.valid_until_index,
            layout.device_key_x_index,
            layout.device_key_y_index,
        ])
        .collect();

    assert_eq!(
        actual, expected,
        "mdoc witness layout drifted; update MDOC_CLAIM_VALUES_WITNESS_START"
    );
    assert_eq!(layout.claim_values_start, MDOC_CLAIM_VALUES_WITNESS_START);
    assert_eq!(
        layout.claim_identifier_hashes_start,
        MDOC_CLAIM_IDENTIFIER_HASHES_WITNESS_START
    );

    for idx in layout.claim_values_range() {
        assert!(
            idx > layout.num_public(),
            "mdoc: normalizedClaimValues[..] is inside the public IO"
        );
    }

    // The device key is a per-credential constant that survives reblinding, so
    // publishing it would let two verifiers correlate every presentation from one
    // credential. Same assertion the JWT layout makes for KeyBindingX/Y.
    for idx in [layout.device_key_x_index, layout.device_key_y_index] {
        assert!(
            idx > layout.num_public(),
            "mdoc: deviceKey is inside the public IO — unlinkability is broken"
        );
    }
}

#[test]
fn show_claim_value_offsets_match_sym() {
    let n_claims = CircuitSize::default().n_claims();
    let layout = calculate_show_witness_indices(n_claims);
    let wanted: Vec<String> = (0..n_claims)
        .map(|i| format!("main.claimValues[{i}]"))
        .chain([
            "main.expressionResult".into(),
            "main.deviceKeyX".into(),
            "main.deviceKeyY".into(),
        ])
        .collect();

    let Some(actual) = witness_indices("show", &wanted) else {
        eprintln!("skipping show: circuit not compiled");
        return;
    };

    let expected: Vec<usize> = layout
        .claim_values_range()
        .chain([
            layout.expression_result_index,
            layout.device_key_x_index,
            layout.device_key_y_index,
        ])
        .collect();

    assert_eq!(
        actual, expected,
        "show witness layout drifted from the compiled circuit; \
         calculate_show_witness_indices is stale (is build/show/ up to date?)"
    );

    for idx in layout.claim_values_range() {
        assert!(
            idx > layout.num_public(),
            "show: claimValues[..] is inside the public IO"
        );
    }
}

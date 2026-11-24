# JSON-LD prepare circuit CLI

The `jsonld` subcommand proves the JSON-LD prepare circuit (`circom/circuits/main/jsonld.circom`,
`circuits.json` entry `jsonld`) and links it to the unchanged Show circuit through
`comm_W_shared`, exactly as `mdoc` does. Run everything from `wallet-unit-poc/ecdsa-spartan2`.

Build needs the circuit compiled first, otherwise `jsonld prove|setup|run` fails with
"JSONLD circuit not compiled into this binary":

    bash ../circom/scripts/compile.sh jsonld     # also needs `show` compiled
    cargo build --release                        # build.rs sets cfg has_circuit_jsonld

On macOS the witnesscalc build needs GMP from Homebrew on the compiler path:
`CPATH=/opt/homebrew/include LIBRARY_PATH=/opt/homebrew/lib cargo build --release`. `build.rs`
embeds an rpath to the witnesscalc dylibs, so `target/release/ecdsa-spartan2` can be exec'd
directly without `cargo run`.

Without compiled circuits only `cargo build --release --no-default-features` works (the
witness path is stubbed out); the native-witness default needs `show` compiled at minimum.

## Subcommands

    cargo run --release -- jsonld setup     [--input FILE] [--size SZ]
    cargo run --release -- jsonld prove     [--input FILE] [--size SZ]
    cargo run --release -- jsonld reblind   [--size SZ]
    cargo run --release -- jsonld verify    [--size SZ]
    cargo run --release -- jsonld run       [--input FILE] [--size SZ]
    cargo run --release -- jsonld benchmark [--input FILE] [--size SZ]
    cargo run --release -- jsonld generate_shared_blinds [--size SZ]
    cargo run --release -- jsonld verify-linked [--json] [--prepare-proof P] [--prepare-vk P]
                                                [--show-proof P] [--show-vk P] [--size SZ]

`--size` only selects the filename prefix (`1k_` by default); the JSON-LD circuit has no size
variants. Relative paths are resolved against the current directory.

| Action | Reads | Writes |
|---|---|---|
| `setup` | `../circom/build/jsonld/jsonld_js/jsonld.r1cs` | `keys/1k_jsonld_proving.key`, `keys/1k_jsonld_verifying.key` |
| `prove` | `--input` (default `../circom/inputs/jsonld/default.json`), proving key, r1cs | `keys/1k_jsonld_instance.bin`, `keys/1k_jsonld_witness.bin`, `keys/1k_jsonld_proof.bin` |
| `reblind` | proving key, instance, witness, `keys/1k_shared_blinds.bin` | overwrites instance, witness, proof |
| `verify` | `keys/1k_jsonld_proof.bin`, `keys/1k_jsonld_verifying.key` | nothing (panics if invalid) |
| `run` | `--input` | nothing (setup, prove, verify in memory) |
| `generate_shared_blinds` | nothing | `keys/1k_shared_blinds.bin` |
| `benchmark` | JSON-LD and Show inputs and keys | all artifacts below, then runs `verify-linked` |

`benchmark` runs the linked flow: shared blinds, prove and reblind JSON-LD with `--input` (default
as above), prove and reblind Show with `../circom/inputs/show/jsonld.json`, verify both, then
`verify-linked` on the resulting files. It needs `jsonld setup` and `show setup` done first. Show
artifacts are `keys/1k_show_{proving.key,verifying.key,instance.bin,witness.bin,proof.bin}`.

The input JSON is passed to witnesscalc as is: numbers become decimal strings, strings must be
decimal integers, nesting is kept, unknown keys are forwarded. `pubKeyX`, `pubKeyY`,
`claimFormats` and `claimFlags` must be present.

Native witness generation does not check constraints on the Rust side: `jsonld prove` on
unsatisfiable inputs can produce a proof that fails verification instead of an error. The jwt, mdoc
and show paths behave the same, since they share `prove_circuit_with_pk` and none checks R1CS
satisfaction before proving. (Circom's generated witness code may still abort on a failing
`assert`, so some bad inputs do error at witness generation.) Always run `verify-linked` before
trusting a proof.

## verify-linked

Verifies the prepare and show proofs and checks that both commit to the same `comm_W_shared`.
It never panics on a bad proof or a missing file; every failure shows up as a `false` flag.

Defaults, each overridable by the flag of the same name:

| Flag | Default |
|---|---|
| `--prepare-proof` | `keys/1k_jsonld_proof.bin` |
| `--prepare-vk` | `keys/1k_jsonld_verifying.key` |
| `--show-proof` | `keys/1k_show_proof.bin` |
| `--show-vk` | `keys/1k_show_verifying.key` |

There are no instance flags: verification reads the commitments from the proofs, never from an
instance file.

Optional expectations (decimal integers; `--expect-issuer-x` and `--expect-issuer-y` must be
given together):

| Flag | Compared against |
|---|---|
| `--expect-issuer-x N`, `--expect-issuer-y N` | `preparePublic.pubKeyX`, `preparePublic.pubKeyY` |
| `--expect-message-hash N` | `showPublic.messageHash` |

With `--json`, stdout carries exactly one JSON object (logs go to stderr for this command):

    {
      "prepareValid": true,
      "showValid": true,
      "commWSharedEqual": true,
      "commWShared": "<hex>",          // bincode of the prepare proof's comm_W_shared; null if it did not load
      "commWSharedShow": "<hex>",      // same for the show proof
      "expressionResult": true,        // Show's predicate evaluated to 1
      "issuerKeyMatches": null,        // true/false when --expect-issuer-* given, else null
      "messageHashMatches": null,      // true/false when --expect-message-hash given, else null
      "preparePublic": {
        "pubKeyX": "<decimal>", "pubKeyY": "<decimal>",
        "claimFormats": ["<decimal>", ...],   // maxClaims = 2 entries
        "claimFlags":   ["<decimal>", ...]
      },
      "showPublic": {
        "expressionResult": "1",
        "messageHash": "<decimal>", "predicateLen": "<decimal>",
        "predicateClaimRefs": [..2], "predicateOps": [..2],
        "predicateRhsIsRef": [..2], "predicateRhsValues": [..2],
        "predicateClaimNames": [[..31], [..31]], "predicateClaimNameLens": [..2],
        "predicateRhsClaimNames": [[..31], [..31]], "predicateRhsClaimNameLens": [..2],
        "tokenTypes": [..8], "tokenValues": [..8], "exprLen": "<decimal>"
      }
    }

`commWShared` and `commWSharedShow` are reported whenever the proof loads, even if it did not
verify, so they are meaningful only together with `prepareValid`/`showValid`. Reblinding gives each
presentation a fresh commitment, so two presentations of one credential should show different
`commWShared` values (unlinkability); equal values mean the same blinds were reused.

All other values are decimal strings. `preparePublic` / `showPublic` are `null` when that proof did not
verify or exposed an unexpected number of public values, so unverified values are never reported.
`prepareValid` / `showValid` mean "the proof verified under the given key".

`expressionResult` (top level) is true only when Show's raw `showPublic.expressionResult` is `"1"`
and Show verified. A proof of a false predicate verifies fine, so it must not pass.

Exit code is 0 only when `prepareValid`, `showValid`, `commWSharedEqual` and `expressionResult` are
all true and no supplied expectation mismatched (`issuerKeyMatches` and `messageHashMatches` are not
`false`). Otherwise it is 1 and the JSON is still printed. An expectation checked against a proof
that did not verify counts as a mismatch. Argument errors exit 1 with a message on stderr and no
JSON. Without `--json` the same flags are printed as text.

**Exit code 0 without the `--expect-*` flags does NOT establish issuer trust, freshness, claim
formats, or the predicate program.** It only means both proofs are valid, they share one witness,
and the predicate they commit to evaluated to true. The caller must check from the JSON that:

- `preparePublic.pubKeyX/pubKeyY` is an issuer key it trusts (or pass `--expect-issuer-*`);
- `showPublic.messageHash` binds the nonce it issued for this presentation (or pass
  `--expect-message-hash`), otherwise a replayed presentation passes;
- `preparePublic.claimFormats` and `claimFlags` are the normalizations its predicates assume;
- `showPublic` predicate fields (`predicateClaimNames`, `predicateOps`, `predicateRhs*`,
  `tokenTypes`, `tokenValues`, `exprLen`, ...) are the predicate program it asked for, since a
  prover can prove any predicate it likes.

## Witness layout

`src/utils.rs` (`calculate_jsonld_output_indices`) assumes no public outputs: public inputs are
`pubKeyX`, `pubKeyY`, `claimFormats[2]`, `claimFlags[2]` at witness 1 to 6. The circuit is
`JSONLD(2240, 2, 128, 31, 64, 252)`, so `maxClaims` is 2, equal to Show's `nClaims`. The private
offsets (`normalizedClaimValues[0]` 2794, `claimIdentifierHashes[0]` 2796, `deviceKeyX` 2798) are
constants in `src/utils.rs`, re-derived from `build/jsonld/jsonld.sym` by
`tests/witness_layout.rs::jsonld_witness_offsets_match_sym`. Recompiling the circuit can move them.

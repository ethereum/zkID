# zkid-input-builder

Shared circuit-input builder for the zkID split RS256 pipeline. Produces
cert-chain (Circuit A) and user-sig (Circuit B) input JSON from card + SMT data.

Consumed by two callers:

- [`ecdsa-spartan2`](../ecdsa-spartan2) — the native Rust prover / CLI
- [`spartan2-wasm`](../spartan2-wasm) — the in-browser prover

Both paths call `generate_split_inputs` via a path dependency, so web and CLI
produce byte-identical input JSON. That guarantee is pinned by
[`spartan2-wasm/tests/input_builder_drift.rs`](../spartan2-wasm/tests/input_builder_drift.rs),
which guards against silent input-shape drift (for example,
`Too many values for input signal __placeholder__`).

Scope is deliberately narrow: cert parsing, bigint chunking, SHA-256 padding,
and `generate_split_inputs`. No Spartan2/prover types leak in.

## Test

```sh
cd wallet-unit-poc/zkid-input-builder
cargo test --release
```

CI runs this under `.github/workflows/web-tests.yaml` alongside the drift guard.

## Public surface

- `generate_split_inputs(user_cert, issuer_cert, user_signature_b64, app_id_bytes, serial_hex, smt_inputs, k_issuer, k_user, max_cert_length, pk_blind, challenge, current_time)`
  — returns `(cert_chain_json, user_sig_json)`. The caller supplies
  `pk_blind` as a decimal-string field element; it is threaded into both
  circuits so the verifier can check `pk_commit_A == pk_commit_B`. Use
  `random_pk_blind()` for fresh per-session sampling in production; pass a
  fixed value when reproducibility matters (drift tests, committed circuit
  fixtures). `challenge` is the verifier-issued per-session field element
  (decimal string) bound into the user-sig proof. `current_time` is the
  decimal string `YYMMDDHHMMSS` (UTC) that the cert-chain circuit checks the
  certificate's validity period against. Circuit B also emits
  `nullifier = ChunkedPoseidonP256(user_rsa_signature)`, deterministic per
  `(card, app_id_bytes)`.
- `APP_ID_LEN = 31` — re-exported constant; `app_id_bytes` must be exactly
  this length.
- `SmtCircuitInputs` — decimal-string field struct matching the Rust/TS
  interchange format used by both provers.
- `current_time_utc()` / `format_current_time(unix_seconds)` — the system
  clock, or a given instant, as `YYMMDDHHMMSS`. Both return an error outside
  2000..=2049, the range a DER `UTCTime` covers. `current_time_utc` is not
  built on wasm32; the browser passes the time in from JS.
- `parse_cert_offsets` — DER offset helpers for the cert-chain circuit's
  byte-range signals.

See `src/split_inputs.rs` for the canonical wiring.

## Why a separate crate

- Keeps the browser build free of transitive Spartan2 / ecdsa-spartan2 native deps.
- Makes the byte-identity guarantee enforceable: a single `generate_split_inputs`
  implementation serialized via `serde_json` with stable key order.
- Lets the wasm drift test depend on both provers without creating a cycle.

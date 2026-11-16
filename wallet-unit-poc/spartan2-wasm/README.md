# spartan2-wasm

Standalone WebAssembly crate that builds the Spartan2 prover used by
[`wallet-unit-poc/web/`](../web). It compiles the three zkID circuits
(`cert_chain_rs2048`, `cert_chain_rs4096`, `user_sig_rs2048`) into a single
`spartan2_wasm.wasm` module with wasm-bindgen + wasm-bindgen-rayon bindings.
Production verification is server-side via
[`go-zkid-verifier`](https://github.com/zkmopro/go-zkid-verifier/pull/8);
`verify` and `link_verify` are for drift tests and debugging.

## Build

```sh
cd wallet-unit-poc/spartan2-wasm

# Native unit tests (fast, no wasm)
cargo test --release --lib

# wasm32 build (requires nightly + rust-src — rust-toolchain.toml pins these)
cargo +nightly build --target wasm32-unknown-unknown --release \
  -Z build-std=panic_abort,std

# Emit JS bindings + snippets/. The wasm-bindgen CLI version must match the
# `wasm-bindgen` crate resolved in Cargo.lock — mismatched versions produce a
# cryptic `BindingsNotSupported` error at runtime. Check with
# `rg '^name = "wasm-bindgen"' Cargo.lock -A1` before installing.
#
#   cargo install wasm-bindgen-cli --version <matching-version>
#
wasm-bindgen --target web --out-dir pkg \
  target/wasm32-unknown-unknown/release/spartan2_wasm.wasm

# Native drift test (slow — setup + prove across two circuits)
cargo test --test native_drift --release

# Input-builder drift test (fast — cross-checks JSON output against
# ecdsa-spartan2's generate_split_inputs)
cargo test --release --test input_builder_drift
```

The drift test reads R1CS artifacts from
`../circom/build/<circuit>/<circuit>_js/<circuit>.r1cs`. Run `yarn compile:all`
from `wallet-unit-poc/circom/` first, or rely on CI's `compile-circuits.yaml`
reusable workflow, which produces the same artifacts.

## JS API

All exports come from the generated `pkg/spartan2_wasm.js`.

- `CircuitKind` — enum with numeric discriminants: `CertChainRs2048 = 0`,
  `CertChainRs4096 = 1`, `UserSigRs2048 = 2`. Pass one of these to every
  circuit-scoped call.
- `init_thread_pool(n)` — re-export from `wasm-bindgen-rayon`. Call once after
  module init with your chosen thread count before any `prove`.
- `load_pk(kind, pkBytes)` — deserialize a bincode proving key and install it
  in the per-circuit slot. One resident PK per `CircuitKind`. Call before the
  first `prove` for that circuit.
- `drop_pk(kind)` — free the installed PK for a given circuit (useful to
  reclaim linear memory after proving completes).
- `prove(kind, wtnsBytes)` → `{ proof, instance, public_values }`. `wtnsBytes`
  is the circom `.wtns` binary, typically produced in JS with circomkit's
  `witness_calculator.js`. `proof` and `instance` are bincode blobs; `public_values`
  is an array of debug-formatted scalar strings.
- `verify(proofBytes, vkBytes)` → `{ valid, public_values, error }`. Wasm-side
  verification. Not used by the production web pipeline — present for the
  drift test and local debugging.
- `link_verify(certPubs, userSigPubs)` → `{ ok, cert_pk_commit, user_sig_pk_commit }`.
  Asserts `pk_commit` equality between a cert-chain and a user-sig proof.
  Inputs are the `public_values` arrays returned by `prove`. Not used in
  production — the server-side verifier performs this check.
- `build_split_inputs(userCertDer, issuerCertDer, userSignatureB64, appIdBytes, serialHex, smtInputs, kIssuer, kUser, challenge, currentTime)` →
  `{ cert_chain, user_sig }`. Builds the cert-chain + user-sig circuit
  input JSON from raw card + SMT data. `appIdBytes` must be exactly 31 bytes —
  the relying-party identifier the cardholder signed. `smtInputs` accepts
  `null` (zero defaults) or a snake_case `SmtCircuitInputs` object. `kIssuer`
  is `17` for RSA-2048 issuers and `34` for RSA-4096. `challenge` is the
  decimal field-element string returned by `go-zkid-verifier`'s `/challenge`
  endpoint, bound into the user-sig proof via a Semaphore-style dummy square.
  `currentTime` is the decimal string `YYMMDDHHMMSS` (UTC); the cert-chain
  proof checks the certificate's validity period against it, and the verifier
  checks it against its own clock.
  `pk_blind` is sampled internally each call via `random_pk_blind()`; callers
  do not pass it. Delegates to the shared
  [`zkid-input-builder`](../zkid-input-builder) crate so the browser produces
  byte-identical JSON to `ecdsa-spartan2`'s `generate_split_inputs`. Parity is
  pinned by `tests/input_builder_drift.rs`.

## Separation from `ecdsa-spartan2`

This crate has no runtime dependency on `ecdsa-spartan2`. The only coupling is
the dev-dependency in `tests/native_drift.rs`, which cross-verifies proofs to
detect transcript drift.

`prove_core` in `src/lib.rs` duplicates the transcript sequence from
`ecdsa-spartan2/src/prover.rs::prove_circuit_in_memory`. If that upstream
function changes (new transcript absorb, reordered calls, different labels),
the drift test fails and this crate must be re-synced.

Three parts of `src/lib.rs` are critical and must not be weakened:
`prove_core` itself (do not inline into the wasm_bindgen entry point — the
native test needs a shared path), the bounded arithmetic in `parse_witness`
(prevents `usize` overflow crashes on 32-bit wasm), and `lock_pk_mut`'s poison
recovery (a panicked prior `prove` must not poison the PK mutex into aborting
the runtime).

## Browser requirements

Rayon-based proving in wasm requires a cross-origin-isolated document:

- Serve the page with `Cross-Origin-Opener-Policy: same-origin` and
  `Cross-Origin-Embedder-Policy: require-corp`.
- Verify at runtime with `self.crossOriginIsolated === true`.

The build flags needed for shared-memory threading are pre-configured in
`.cargo/config.toml`: `-C target-feature=+atomics,+bulk-memory,+mutable-globals`
and `-C link-arg=--shared-memory --import-memory --max-memory=4294967296`. No
extra flags from consumers.

## Thread-count guidance

The web app picks `clamp(navigator.hardwareConcurrency - 1, 2, 8)`. Leaving one
core for the main thread keeps the UI responsive. The 8-thread cap is
intentional: wasm32 has a 4 GB linear-memory ceiling, and
`certChainRS4096` can approach that limit at higher thread counts.

## Drift test

`tests/native_drift.rs` exists because transcript divergence between this crate
and `ecdsa-spartan2` can produce proofs that the other side cannot verify.

The test runs setup locally (so it does not depend on committed PK artifacts),
calls `prove_core` here to produce a proof and instance, then deserializes
both into the concrete Spartan2 types exported from `ecdsa-spartan2` and calls
`verify_circuit_with_loaded_data` to confirm acceptance. It covers at least one
cert-chain variant and user-sig.

The test runs in CI via `web-tests.yaml` on every PR that touches
`spartan2-wasm/` or `ecdsa-spartan2/src/prover.rs`, and can be run locally on
demand with `cargo test --test native_drift --release`.

If it fails, re-sync `prove_core` with
`ecdsa-spartan2/src/prover.rs::prove_circuit_in_memory` (transcript absorbs,
labels, and call order). Do not patch the test to pass; patch the prover.

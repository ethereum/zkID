# zkID Circuits

Circom circuits for X.509 RSA-SHA256 certificate chain verification with
revocation, used by the [zkID wallet PoC](../).

Compiled with [circomkit](https://github.com/erhant/circomkit) on the
secq256r1 prime field; proven by the Rust prover in
[`../ecdsa-spartan2`](../ecdsa-spartan2).

## Compile

```sh
yarn install

# Compile a single circuit
yarn compile:certChainRS2048
yarn compile:certChainRS4096
yarn compile:userSigRS2048

# Compile all
yarn compile:all
```

Use `yarn compile:all` rather than calling `npx circomkit compile` directly —
the script handles R1CS placement and copies the C++ witness calculator to
`build/cpp/`.

## Test

```sh
yarn test
```

Tests use `circom_tester` and run under mocha. The script sets
`NODE_OPTIONS=--max-old-space-size=16384` because the RS256 circuits are
memory-heavy.

## Layout

- `circuits/main/` — top-level circuit entry points (one file per build target)
- `circuits/rs256.circom` — RS256 cert verification and shared templates
- `circuits/certChain.circom` — CertChain circuit (Circuit A: cert chain + revocation + pkCommit)
- `circuits/userSig.circom` — UserSig circuit (Circuit B: user signature + pkCommit)
- `circuits/components/` — reusable templates: SMT non-membership, Poseidon over P256
- `circuits/utils/utils.circom` — DER-level cert helpers (TBS / serial extraction, modulus extraction, byte packing, Poseidon-over-bytes)

## Public-output layout (verifier-side parsing)

Witness order (after the implicit constant-1 wire):

| Circuit              | Signals | Order                                                               |
|----------------------|---------|---------------------------------------------------------------------|
| `certChainRS2048`  | 20      | `[pkCommit, issuerRsaModulus[17], smtRoot, currentTime]`            |
| `certChainRS4096`  | 37      | `[pkCommit, issuerRsaModulus[34], smtRoot, currentTime]`            |
| `userSigRS2048`  |  4      | `[pkCommit, nullifier, appIdPacked, challenge]`                     |

`appIdPacked` is `tbs[0..31]` packed little-endian into one field element;
the verifier matches it against the configured `APP_ID` after the same
packing. `challenge` is the verifier-issued per-session field element bound
via a Semaphore-style dummy square (`challengeSquared <== challenge * challenge`).

## See also

- [SPEC.md](./SPEC.md) — circuit specification (inputs, outputs, what's proven)
- [`../ecdsa-spartan2/README.md`](../ecdsa-spartan2/README.md) — Rust prover CLI usage

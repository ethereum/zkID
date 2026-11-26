# Initial Formal Verification Findings (Reproducer Tests)

This document summarizes nine bugs and circuit/SDK mismatches discovered during an **initial round of formal verification** of the OpenAC non-mDOC Circom circuits (compiled at `9557067` with Circom `2.2.3`, `--O2 --prime secq256r1`) and their `openac-sdk` input builders.

This branch intentionally **does not modify production circuit or SDK code**. It adds self-contained failing unit tests (plus passing control cases) to demonstrate each issue reproducibly for team review and fix discussion.

---

## Summary of Findings

| # | Category | Component | Summary | Reproducer Test(s) |
| --- | --- | --- | --- | --- |
| **1** | **Soundness (Gadget)** | `Secp256r1AddComplete` | Underconstrained doubling branch (`P == Q`): `lambdaA` is unconstrained, allowing an arbitrary slope and off-curve forged outputs | [`circom/tests/circuits/p256-add-complete.test.ts`](./circom/tests/circuits/p256-add-complete.test.ts) |
| **2** | **Completeness** | `Secp256r1Mul` / `ECDSA` | Scalars `s ∈ {0, 1, q - 2, q - 1}` cause `accComplete[1]` to hit `𝒪 = (0, 0)`, making `accComplete[2]` unsatisfiable (`0 === -3`); rejects valid low-S signatures with `m = 0` or `s = (q - 1)/2` | [`circom/tests/circuits/p256-mul-left-infinity.test.ts`](./circom/tests/circuits/p256-mul-left-infinity.test.ts) |
| **3** | **Completeness / Spec** | `ECDSA` | Final check `r === R.outX` compares in `F_p` without reducing `R.outX mod q`, rejecting FIPS 186-5 valid signatures with `q ≤ R.x < p` | [`circom/tests/circuits/ecdsa-high-x.test.ts`](./circom/tests/circuits/ecdsa-high-x.test.ts) |
| **4** | **Spec Mismatch** | `HashModScalarField` | `Bits2Num(256)` reduces modulo `p` before reducing modulo `q`, computing `(D mod p) mod q` instead of `D mod q` whenever `D ≥ p` | [`circom/tests/circuits/hash_mod.test.ts`](./circom/tests/circuits/hash_mod.test.ts) |
| **5** | **Circuit / SDK Mismatch** | `ClaimHasher` / `encodeClaims` | `ClaimHasher(2, 128)` always hashes 128 bytes (2 SHA blocks), while `encodeClaims` emits 1-block padding for disclosures ≤ 55 bytes, producing a wrong digest | [`circom/tests/circuits/claim-hasher-padding.test.ts`](./circom/tests/circuits/claim-hasher-padding.test.ts), [`openac-sdk/tests/credential.test.ts`](./openac-sdk/tests/credential.test.ts) |
| **6** | **Completeness** | `PayloadExtractor` (JWT 2k) | `CountCharOccurrences(..., 46)` counts `.` across the entire SHA-padded buffer; for raw lengths `1472..1503`, the SHA-256 bit-length suffix contains byte `0x2e` (`'.'`), breaking `periodCount === 1` | [`circom/tests/circuits/jwt-payload-padding.test.ts`](./circom/tests/circuits/jwt-payload-padding.test.ts) |
| **7** | **Circuit / SDK Mismatch** | `selectVcSizeForSigningInput` / `ES256` & `PayloadExtractor` | `Num2Bits(log2Ceil(maxMessageLength))` requires padded length strictly `< maxMessageLength` on power-of-two profiles (`2k`/`4k`/`8k`), giving raw limits `1975`/`4023`/`8119`, while the SDK selects by raw length `≤ maxMessageLength` (`1280`/`2048`/`4096`/`8192`) | [`openac-sdk/tests/jwt-signing-length.test.ts`](./openac-sdk/tests/jwt-signing-length.test.ts), [`circom/tests/circuits/jwt-payload-padding.test.ts`](./circom/tests/circuits/jwt-payload-padding.test.ts) |
| **8** | **Circuit / SDK Mismatch** | `selectVcSizeForSigningInput` / `buildJwtCircuitInputs` / `PayloadExtractor` | Profile selection ignores `maxB64PayloadLength` (`960` in `1k`, `4000` in `4k`), routing valid credentials to a profile that throws in `buildJwtCircuitInputs`; in `jwt_1k`, `GreaterThan(10)` also hard-caps `b64PayloadLength ≤ 1024` inside the circuit | [`openac-sdk/tests/jwt-1k-payload-length.test.ts`](./openac-sdk/tests/jwt-1k-payload-length.test.ts), [`circom/tests/circuits/jwt-1k-payload-length.test.ts`](./circom/tests/circuits/jwt-1k-payload-length.test.ts) |
| **9** | **Completeness** | `K_add` / `Secp256r1Mul` / `ECDSA` | `K_add` drops the low-limb carry (`slo + tQlo ≥ 2^128`) when computing `klo`/`khi`, causing `kloBits = Num2Bits(128)` to reject ~`0.48 × 2^224` valid canonical scalars `s < q - tQ` and valid low-S ECDSA signatures | [`circom/tests/circuits/p256-kadd-carry.test.ts`](./circom/tests/circuits/p256-kadd-carry.test.ts) |

---

## How to Run the Reproducers

### SDK tests (`wallet-unit-poc/openac-sdk`)

```bash
cd wallet-unit-poc/openac-sdk
npx vitest run \
  tests/jwt-signing-length.test.ts \
  tests/jwt-1k-payload-length.test.ts \
  tests/credential.test.ts
```

Expected on `9557067`: **22 passed, 7 failed** (`jwt-signing-length.test.ts`: 4 failed; `jwt-1k-payload-length.test.ts`: 3 failed; `credential.test.ts`: 17 passed including the 55/56-byte padding control).

### Circom circuit tests (`wallet-unit-poc/circom`)

Requires `circom` (`2.2.3`) on `PATH` and dependencies installed (`yarn`).

```bash
cd wallet-unit-poc/circom
NODE_OPTIONS=--max-old-space-size=16384 npx tsx ./node_modules/mocha/bin/mocha.js \
  --no-config --extension ts --timeout 900000 \
  tests/circuits/p256-add-complete.test.ts \
  tests/circuits/p256-mul-left-infinity.test.ts \
  tests/circuits/p256-kadd-carry.test.ts \
  tests/circuits/ecdsa-high-x.test.ts \
  tests/circuits/hash_mod.test.ts \
  tests/circuits/claim-hasher-padding.test.ts \
  tests/circuits/jwt-payload-padding.test.ts \
  tests/circuits/jwt-1k-payload-length.test.ts
```

Expected on `9557067`: **14 passing, 21 failing** (every control passes; all 21 bug reproducers fail across Findings 1–9). Each file can also be run individually by passing just its path.

---

## Detailed Findings

### 1. `Secp256r1AddComplete` underconstrained doubling branch (`P == Q`)

- **Severity / Type:** Soundness (gadget-level underconstraint)
- **Source:** [`circom/circuits/ecdsa/p256/add.circom` (L92–L108)](./circom/circuits/ecdsa/p256/add.circom#L92-L108)
- **Root cause:**
  When `xP == xQ` (`dx = 0`, `isXEqual.out = 1`), the witness generator sets `lambdaA <-- 0`, and the constraint on `lambdaA` is:
  ```circom
  dx * lambdaA === dy;
  signal lambda <== (lambdaB * isXEqual.out) + lambdaA;
  ```
  For finite point doubling (`xP == xQ` and `yP == yQ`, so `dx = 0` and `dy = 0`), `0 * lambdaA === 0` holds for **every** `lambdaA ∈ F_p`, yet `lambdaA` is added directly into `lambda`. A malicious prover can pick any `lambdaA` to shift `lambda = lambdaB + lambdaA` to any desired field value, producing an arbitrary off-curve `(outX, outY)` that satisfies every R1CS constraint of `Secp256r1AddComplete`.
  *(Full ECDSA exploitability depends on whether an equal-point doubling branch is reachable inside `Secp256r1Mul` or the final `ECDSA` addition, which remains to be ruled out or fixed at the gadget level.)*
- **Reproducer:** [`circom/tests/circuits/p256-add-complete.test.ts`](./circom/tests/circuits/p256-add-complete.test.ts)
  - Passes: honest doubling `(G, G) -> 2G`; rejects tampering `lambdaA` on distinct points `(G, 2G)`.
  - Fails (2 cases): forged witnesses on `(G, G)` with `lambdaA = 1` and `lambdaA = -lambdaB` (`lambda = 0`) yield off-curve outputs yet pass all R1CS constraints (`expectConstraintFail` fails).
- **Discussion / Fix direction:** Constrain `lambdaA * isXEqual.out === 0` (or gate `lambdaA` with `(1 - isXEqual.out)` when forming `lambda`, matching the witness assignment).

---

### 2. `Secp256r1Mul` left-infinity completeness failure for `s ∈ {0, 1, q - 2, q - 1}`

- **Severity / Type:** Completeness (circuit rejects valid canonical scalars and FIPS 186-5 low-S signatures)
- **Source:** [`circom/circuits/ecdsa/p256/mul.circom` (L70–L100)](./circom/circuits/ecdsa/p256/mul.circom#L70-L100), [`circom/circuits/ecdsa/p256/add.circom` (L99–L100)](./circom/circuits/ecdsa/p256/add.circom#L99-L100)
- **Root cause:**
  `Secp256r1Mul` recodes `s` via `K_add()` (`s + 2^256 - 2 - q`) and runs 253 incomplete steps followed by three `Secp256r1AddComplete` stages `accComplete[0..2]` and a final `out` addition. For the four valid scalars `s ∈ {0, 1, q - 2, q - 1}`, the running multiple after `accComplete[1]` hits `q • P = 𝒪 = (0, 0)`, which is then wired into the **left** operand `(xP, yP)` of `accComplete[2]`. Because `Secp256r1AddComplete` unconditionally enforces the tangent-slope equation:
  ```circom
  lambdaB * 2 * yP === 3 * xPSquared - 3;
  ```
  plugging `(xP, yP) = (0, 0)` produces `0 === -3`, which is unsatisfiable. In `ECDSA`, this rejects valid FIPS 186-5 low-S signatures whenever `m = 0` (via `m * s^-1 * G`), or whenever `s^-1 ∈ {1, q - 2, q - 1}` (for example `s = (q - 1) / 2`, which is canonical low-S and has `s^-1 = q - 2`).
- **Reproducer:** [`circom/tests/circuits/p256-mul-left-infinity.test.ts`](./circom/tests/circuits/p256-mul-left-infinity.test.ts)
  - Passes: boundary neighbors `s = 2` and `s = q - 3`.
  - Fails (6 cases): `Secp256r1Mul` fails on `s ∈ {0, 1, q - 2, q - 1}`; `ECDSA` fails on valid low-S signatures with `m = 0` and with `s = (q - 1) / 2`.
- **Discussion / Fix direction:** Gate the tangent-slope constraint in `Secp256r1AddComplete` when `xP == 0 && yP == 0` (e.g., substitute a dummy nonzero `yP` or multiply by `(1 - isPZero)`), or ensure `Secp256r1Mul` cannot pass `(0, 0)` as the left operand.

---

### 3. `ECDSA` final check `r === R.outX` omits reduction modulo `q`

- **Severity / Type:** Completeness / FIPS 186-5 specification mismatch
- **Source:** [`circom/circuits/ecdsa/ecdsa.circom` (L100)](./circom/circuits/ecdsa/ecdsa.circom#L100)
- **Root cause:**
  Standard ECDSA (FIPS 186-5 §6.4.2) accepts when `R.x mod q == r`. The circuit instead checks `r === R.outX` directly in `F_p`, rejecting valid signatures whose verification point has `q ≤ R.x < p` (probability `(p - q) / p ≈ 2^-128` for random signatures, but deterministically constructible).
- **Reproducer:** [`circom/tests/circuits/ecdsa-high-x.test.ts`](./circom/tests/circuits/ecdsa-high-x.test.ts)
  - Passes: control signature with `R.x < q`.
  - Fails (1 case): concrete FIPS 186-5 valid low-S signature with `r = 3`, `u1 = 2`, `u2 = 4`, and `R.x = q + 3 ∈ [q, p)` (verified by `@noble/curves`), rejected by `ecdsa.circom:100`.
- **Discussion / Fix direction:** Reduce `R.outX` modulo `q` (a single conditional subtraction of `q` when `R.outX ≥ q`, since `p < 2q`), or explicitly document `R.x < q` as a domain restriction if intentionally omitted.

---

### 4. `HashModScalarField` computes `(D mod p) mod q` instead of `D mod q`

- **Severity / Type:** Specification mismatch between circuit and SDK
- **Source:** [`circom/circuits/utils/utils.circom` (L226–L235)](./circom/circuits/utils/utils.circom#L226-L235), [`openac-sdk/src/inputs/jwt-input-builder.ts` (L69–L75)](./openac-sdk/src/inputs/jwt-input-builder.ts#L69-L75)
- **Root cause:**
  `HashModScalarField` feeds all 256 SHA-256 digest bits into `Bits2Num(256)`, which evaluates in the native base field `F_p` (wrapping `D` to `D mod p`) before comparing with `q`. Whenever `D ≥ p` (probability `(2^256 - p) / 2^256 ≈ 2^-32`), the circuit computes `(D mod p) mod q` instead of `D mod q`, diverging from standard ECDSA / `@noble/curves`.
- **Reproducer:** [`circom/tests/circuits/hash_mod.test.ts`](./circom/tests/circuits/hash_mod.test.ts)
  - Passes: `q - 1`, `q`, `q + 1`, `p - 1`.
  - Fails (3 cases): `p`, `p + 1`, and `2^256 - 1` (all return `(D mod p) mod q` instead of `D mod q`).
- **Discussion / Fix direction:** Perform the `D ≥ q` comparison on the 256-bit representation (or split into 128-bit limbs) before converting to `F_p`, so `D ≥ p` subtracts `q` directly without an intermediate `mod p` wrap.

---

### 5. `ClaimHasher(2, 128)` vs. SDK `encodeClaims` one-block disclosure padding

- **Severity / Type:** Circuit / SDK mismatch (breaks short disclosures ≤ 55 bytes)
- **Source:** [`circom/circuits/components/claim-decoder.circom` (L94–L105)](./circom/circuits/components/claim-decoder.circom#L94-L105), [`openac-sdk/src/utils.ts` (L159–L175)](./openac-sdk/src/utils.ts#L159-L175)
- **Root cause:**
  `ClaimHasher(maxMatches, 128)` hardcodes `claimHasher[i].paddedInLength <== maxClaimsLength` (`128`, always hashing 2 SHA-256 blocks). However, `encodeClaims` calls `sha256Pad(utf8Bytes, 128)`, which places the `0x80` delimiter and 64-bit length at the end of **block 1** (bytes `0..63`) and zero-fills bytes `64..127` whenever a Base64url disclosure is `≤ 55` bytes (1-block SHA message). Hashing all 128 bytes compresses an extra all-zero second block, producing a digest that never matches the issuer's SD-JWT `_sd` digest.
- **Reproducer:** [`circom/tests/circuits/claim-hasher-padding.test.ts`](./circom/tests/circuits/claim-hasher-padding.test.ts) and [`openac-sdk/tests/credential.test.ts`](./openac-sdk/tests/credential.test.ts)
  - Passes: 56-byte disclosure (2 padded blocks) in `ClaimHasher(2, 128)`; 55-byte disclosure in `ClaimHasher(1, 64)`; SDK test confirming `encodeClaims` writes 1-block padding at 55 bytes and 2-block padding at 56 bytes.
  - Fails (1 case): 55-byte disclosure in `ClaimHasher(2, 128)` produces a different digest from Node `crypto.createHash("sha256")`.
- **Discussion / Fix direction:** Pass each claim's actual padded length (`64` or `128`) into `ClaimHasher` (matching `ES256`), or enforce a minimum disclosure length `≥ 56` bytes (e.g., minimum salt length) across the protocol and SDK.

---

### 6. JWT 2k `PayloadExtractor` counts periods inside SHA-256 padding (`raw ∈ [1472, 1503]`)

- **Severity / Type:** Completeness (valid SD-JWTs rejected in a 32-byte length window)
- **Source:** [`circom/circuits/jwt_tx_builder/header-payload-extractor.circom` (L85–L86)](./circom/circuits/jwt_tx_builder/header-payload-extractor.circom#L85-L86), [`openac-sdk/src/utils.ts` (L118)](./openac-sdk/src/utils.ts#L118)
- **Root cause:**
  `PayloadExtractor` enforces `CountCharOccurrences(maxMessageLength)(message, 46) === 1` across the **entire** SHA-256-padded buffer `message`, including the 8-byte big-endian bit-length suffix. Whenever `rawLength ∈ [1472, 1503]`, the bit length `rawLength * 8` lies in `[0x2e00, 0x2ef8]`, so its second-to-last byte is `0x2e = 46 = '.'`. Together with the JWT header/payload delimiter, `periodCount` becomes `2` and the circuit rejects the credential. (Any longer profile whose supported range contains a multiple of `256` with high byte `0x2e`, e.g. `1472..1503` in `2k`/`4k`/`8k`, hits the same suffix byte.)
- **Reproducer:** [`circom/tests/circuits/jwt-payload-padding.test.ts`](./circom/tests/circuits/jwt-payload-padding.test.ts)
  - Passes: `1471`, `1504`, `1975` signing bytes (controls).
  - Fails (2 cases): `1472` and `1503` signing bytes fail `periodCount === 1`.
- **Discussion / Fix direction:** Count periods only over the unpadded signing prefix (`i < firstPaddingMarker`, i.e., before the `0x80` byte) rather than across all `maxMessageLength` bytes.

---

### 7. SDK profile selection vs. strict `< maxMessageLength` padded-length circuit bound (`2k`/`4k`/`8k`)

- **Severity / Type:** Circuit / SDK mismatch (top block of each profile rejected in-circuit)
- **Source:** [`openac-sdk/src/sizing.ts` (L70–L73)](./openac-sdk/src/sizing.ts#L70-L73), [`openac-sdk/src/prover.ts` (L93)](./openac-sdk/src/prover.ts#L93), [`circom/circuits/utils/es256.circom` (L26–L27)](./circom/circuits/utils/es256.circom#L26-L27), [`circom/circuits/jwt_tx_builder/header-payload-extractor.circom` (L74)](./circom/circuits/jwt_tx_builder/header-payload-extractor.circom#L74)
- **Root cause:**
  Two stacked discrepancies occur at the upper end of every profile:
  1. `selectVcSizeForSigningInput(byteLength)` compares the **raw** signing length against `maxMessageLength` (`1280`/`2048`/`4096`/`8192`) without reserving the 9+ bytes of SHA-256 padding (e.g., `1272` raw bytes selects `"1k"` even though `sha256Pad` requires `1344 > 1280`).
  2. In both `ES256` and `PayloadExtractor`, `Num2Bits(log2Ceil(maxMessageLength))` constrains `messageLength < 2^log2Ceil(maxMessageLength)`. For power-of-two profiles (`2k`: `2048`, `4k`: `4096`, `8k`: `8192`), `2^log2Ceil(maxMessageLength) == maxMessageLength`, so a padded length equal to `maxMessageLength` is **rejected** by `Num2Bits`. The actual maximum raw signing lengths accepted by the circuits are therefore `1271` (`1k`), `1975` (`2k`), `4023` (`4k`), and `8119` (`8k`).
- **Reproducer:** [`openac-sdk/tests/jwt-signing-length.test.ts`](./openac-sdk/tests/jwt-signing-length.test.ts) and [`circom/tests/circuits/jwt-payload-padding.test.ts` (L64–L72)](./circom/tests/circuits/jwt-payload-padding.test.ts#L64-L72)
  - Passes: last fitting lengths `1271`, `1975`, `4023`, `8119`; Circom diagnostic confirming `PayloadExtractor(2048, 2000)` rejects `1976` raw bytes (`messageLength = 2048`) inside `Num2Bits`.
  - Fails (4 cases in SDK): `1272 -> "2k"`, `1976 -> "4k"`, `4024 -> "8k"`, and `8120 -> throw InputError`.
- **Discussion / Fix direction:** Either widen the circuit bit-checks to `Num2Bits(log2Ceil(maxMessageLength + 1))` and account for SHA padding in `selectVcSizeForSigningInput`, or tighten `selectVcSizeForSigningInput` to the exact circuit limits (`1271`, `1975`, `4023`, `8119`).

---

### 8. SDK profile selection ignores `maxB64PayloadLength`, and `jwt_1k` hard-caps `b64PayloadLength ≤ 1024`

- **Severity / Type:** Circuit / SDK mismatch
- **Source:** [`openac-sdk/src/sizing.ts` (L6–L35, L70–L73)](./openac-sdk/src/sizing.ts#L6-L35), [`openac-sdk/src/inputs/jwt-input-builder.ts` (L41–L45)](./openac-sdk/src/inputs/jwt-input-builder.ts#L41-L45), [`circom/circuits/jwt_tx_builder/array.circom` (L15–L30)](./circom/circuits/jwt_tx_builder/array.circom#L15-L30)
- **Root cause:**
  `selectVcSizeForSigningInput` selects a circuit size solely from `signingInputByteLength`, ignoring each profile's `maxB64PayloadLength` (`960` for `1k`, `4000` for `4k`).
  - For a standard 44-byte header (`{"alg":"ES256","typ":"vc+sd-jwt"}`), any credential with `b64PayloadLength ∈ [961, 1226]` has `signingLength ≤ 1271`, so the SDK selects `"1k"` and then immediately throws `Payload length (...) exceeds maxB64PayloadLength (960)` in `buildJwtCircuitInputs`.
  - Similarly, for a minimal 20-byte header (`{"alg":"ES256"}`), `b64PayloadLength ∈ [4001, 4002]` has `signingLength ≤ 4023`, so `"4k"` is selected and fails its `4000`-char payload limit.
  - Inside the compiled `jwt_1k` circuit (`PayloadExtractor(1280, 960)`), `SelectSubArrayBase64(1280, 960)` uses `GreaterThan(log2Ceil(960))` = `GreaterThan(10)`, whose `Num2Bits(11)` hard-rejects `b64PayloadLength > 1024` (and truncates payloads in `961..1024` to 960 glyphs).
- **Reproducer:** [`openac-sdk/tests/jwt-1k-payload-length.test.ts`](./openac-sdk/tests/jwt-1k-payload-length.test.ts) and [`circom/tests/circuits/jwt-1k-payload-length.test.ts`](./circom/tests/circuits/jwt-1k-payload-length.test.ts)
  - Passes: 960-char payload control in both SDK and Circom.
  - Fails (3 SDK cases + 1 Circom case): SDK fails on `1k` @ `964`, `1k` @ `1026`, and `4k` @ `4002`; Circom `PayloadExtractor(1280, 960)` fails on `1026` (`1071 ≤ 1271` signing bytes).
- **Discussion / Fix direction:** Pass both `signingInputByteLength` and `b64PayloadLength` into profile selection so credentials are routed to the smallest profile satisfying both `maxMessageLength` (after SHA padding) and `maxB64PayloadLength`.

---

### 9. `K_add` drops low-limb carry when `s < q - tQ` and `slo + tQlo ≥ 2^128`

- **Severity / Type:** Completeness (circuit rejects ~`0.48 × 2^224` valid canonical scalars and FIPS 186-5 low-S signatures)
- **Source:** [`circom/circuits/ecdsa/p256/mul.circom` (L205–L244)](./circom/circuits/ecdsa/p256/mul.circom#L205-L244)
- **Root cause:**
  `K_add()` computes `carry = (slo + tQlo) >> 128` and correctly folds it into the carry-propagated limbs `alo = slo + tQlo - carry * 2^128` and `ahi = shi + tQhi + carry` for the `s + tQ >= q` comparison (`isQuotientOne`). However, lines 233–241 then revert to the raw un-carried sums `slo + tQlo` and `shi + tQhi`:
  ```circom
  theta.in[1] <== slo + tQlo;
  ...
  signal klo <== (slo + tQlo + borrow.out * (2 ** 128)) - isQuotientOne.out * qlo;
  signal khi <== (shi + tQhi - borrow.out * 1)  - isQuotientOne.out * qhi;
  ```
  When `isQuotientOne == 1`, the omitted carry happens to cancel with the omitted borrow (since `tQlo < qlo`). When `isQuotientOne == 0` (`s < q - tQ`) and `slo + tQlo ≥ 2^128`, `borrow.out == 0`, leaving `klo = slo + tQlo ≥ 2^128`, which makes `kloBits = Num2Bits(128)` unsatisfiable. This rejects `((q - tQ) >> 128) * tQlo ≈ 0.48 × 2^224` valid canonical scalars (including `s = 2^128 - tQlo` through `s = 2^128 - 1`) and any otherwise-valid ECDSA signature where `m`, `r`, or `s⁻¹` falls in this region.
- **Reproducer:** [`circom/tests/circuits/p256-kadd-carry.test.ts`](./circom/tests/circuits/p256-kadd-carry.test.ts)
  - Passes (2 controls): `K_add` on `s = 2^128 - tQlo - 1` (just below carry threshold) and `s = q - tQ` (`isQuotientOne = 1`); `Secp256r1Mul` on `s = 2^128 - tQlo - 1`.
  - Fails (5 cases): `K_add` fails `Num2Bits(128)` on `s = 2^128 - tQlo` (smallest failing scalar), `s = 2^128 - 1`, and `((q - tQ) >> 128) * 2^128 - 1` (largest failing scalar); `Secp256r1Mul` fails on `s = 2^128 - 1`; `ECDSA` rejects a valid low-S signature with `m = 2^128 - 1` (isolated from Findings 1–3).
- **Discussion / Fix direction:** Replace `slo + tQlo` and `shi + tQhi` on lines 233, 240, and 241 with the already-computed carry-propagated signals `alo` and `ahi` (0 extra constraints).

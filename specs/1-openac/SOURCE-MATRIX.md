# OpenAC Core Source Matrix

This note records how the raw `1/OPENAC` draft was derived.

Primary external references:

- [OpenAC whitepaper](https://eprint.iacr.org/2026/251)
- [openac-sdk reference implementation](https://github.com/ethereum/zkID/tree/main/wallet-unit-poc/openac-sdk)

## Status Labels

- `Implemented`: visible in the current `openac-sdk` behavior.
- `Profile-standardized`: implemented behavior that the spec now fixes within
  the current `SD-JWT-P256` profile, but not as a cross-profile core rule.
- `Paper-backed`: described in the OpenAC paper but not fully standardized in
  the SDK surface.
- `Excluded`: intentionally left out of the raw core spec.
- `Compatibility note`: visible current behavior that the core spec documents
  without adopting as a required long-term semantic.

## Matrix

| Topic | Primary Source | Status | Treatment in `1/OPENAC` |
| --- | --- | --- | --- |
| Two-phase `Prepare` / `Show` model | `openac-sdk` README, `paper/zkID_construction.tex` | Implemented | Normative core structure |
| Linked proofs over shared witness values | `paper/zkID_construction.tex`, `src/wasm-bridge.ts` | Implemented | Normative requirement; construction remains abstract |
| Internal commitment-consistency check during verification | `src/wasm-bridge.ts` | Implemented | Normative verifier requirement; backend mechanism left unspecified |
| `SD-JWT` credential input with disclosures | `src/credential.ts`, `src/inputs/jwt-input-builder.ts` | Implemented | Normative profile content |
| Issuer signature algorithm `ES256` / `P-256` | `src/inputs/jwt-input-builder.ts` | Implemented | Normative for `SD-JWT-P256` profile |
| Device-binding key from `payload.cnf.jwk` | `src/credential.ts` | Implemented | Normative for `SD-JWT-P256` profile |
| Device-binding signature over verifier nonce | `src/inputs/show-input-builder.ts` | Implemented | Normative |
| Challenge hashing as `SHA-256(UTF8(challenge)) mod q_P256` | `src/inputs/show-input-builder.ts` | Implemented | Normative |
| Primitive predicates `LE`, `GE`, `EQ` | `src/inputs/show-input-builder.ts` | Implemented | Normative |
| Postfix logic tokens `REF`, `AND`, `OR`, `NOT` | `src/inputs/show-input-builder.ts` | Implemented | Normative |
| Binary proof bundle with five length-prefixed fields | `src/prover.ts` | Implemented | Normative |
| Bundle `version` field currently populated from `SDK_VERSION` | `src/prover.ts` | Compatibility note | Core assigns protocol/profile semantics to the field; current SDK semver usage is legacy |
| JSON proof convenience form | `src/prover.ts` | Implemented | Informative |
| Circuit parameter defaults | `src/types.ts` | Implemented | Recorded as recommended defaults |
| Public output `expressionResult` | `src/verifier.ts` | Implemented | Normative core semantic |
| Shared-witness commitment equality `comm_W_shared` | `wallet-unit-poc/openac-sdk/wasm/src/lib.rs`, `wallet-unit-poc/ecdsa-spartan2/src/circuits/prepare_circuit.rs`, `wallet-unit-poc/ecdsa-spartan2/src/circuits/show_circuit.rs` | Implemented | Normative linking mechanism for this profile. The commitment is hiding and re-randomized per session, so it binds the device key used in `Prepare` to the device-binding signature verified in `Show` without exposing a stable identifier. |
| Claim normalization transport via `normalizedClaimValues` | `src/inputs/show-input-builder.ts`, tests | Implemented | Normative transport only; semantics remain profile-specific |
| `claimFormats` tags `0=bool, 1=uint, 2=iso_date, 3=roc_date, 4=string` | `circom/circuits/jwt.circom`, `circom/circuits/components/claim-value-normalizer.circom`, tests | Profile-standardized | Normative for `SD-JWT-P256` only; not a core registry |
| Hyrax commitments and Tom256-specific backend details | `paper/zkID_construction.tex` | Paper-backed | Informative only |
| `prepareBatch` / batch re-randomization vocabulary | `paper/zkID_construction.tex` | Paper-backed | Not standardized in wire protocol |
| Revocation | architecture note, other repos/specs | Excluded | Deferred to future extension |
| Nullifiers | architecture note, other specs | Excluded | Deferred to future extension |
| `mdoc` and `X.509` profiles | architecture note, paper context | Excluded | Deferred to future profile specs |
| On-chain verifier interface | architecture note | Excluded | Deferred |
| Generalized cross-credential predicates | architecture note | Excluded | Deferred |

## Draft-Candidate Resolutions

### 1. Scope

Core remains intentionally narrow: two-phase proving, linking, verifier
requirements, proof-bundle handling, and the current `SD-JWT-P256` profile.
Revocation, nullifiers, on-chain interfaces, and additional credential
containers remain excluded.

### 2. Device key handling

The device-binding public key MUST NOT be a verifier-visible output of
`Show` in either Core or this profile. The unlinkable device binding is
provided by the shared-witness construction: both circuits share the
witness layout `[KeyBindingX, KeyBindingY, claimValues...]`; the holder
samples fresh shared blinds per session and reblinds both proofs; the
verifier enforces
`prepare_instance.comm_W_shared == show_instance.comm_W_shared`. Because
the shared-witness commitment is hiding and re-randomized per
presentation, it binds Prepare's extracted device key to Show's signing
key without exposing a stable verifier-observable identifier.

### 3. Versioning

The bundle `version` field is now treated as protocol/profile metadata rather
than SDK release metadata, even though the current implementation still writes
`SDK_VERSION`.

### 4. Claim normalization

Core still avoids a cross-profile normalization registry, but the currently
visible `SD-JWT-P256` format tags are now fixed at the profile layer from the
circom implementation and tests.

### 5. Linking construction

The linking property remains normative, while the Hyrax/Tom256-specific
construction described in the paper remains informative.

### 6. Challenge encoding

Challenge byte encoding is profile-specific. For `SD-JWT-P256`, the
verifier-supplied `challenge_bytes` are hashed with SHA-256 and reduced
mod `q_P256` to produce the in-circuit `challenge_scalar`. The three values
(`challenge_bytes`, `challenge_digest`, `challenge_scalar`) are kept
terminologically distinct so that external ECDSA signing or verification is
not conflated with the circuit's field-element encoding.

### 7. Proof validity versus policy acceptance

Proof validity and policy acceptance remain separate verifier-side concepts.
A presentation with `expression_result = 0` may verify cryptographically but
is not acceptable for authorization. The SDK exposes both `proofValid` and
`expression_result`; the verifier owns the authorization decision.

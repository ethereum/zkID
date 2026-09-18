---
slug: 3
title: 3/ZK-AGE-VERIFICATION
name: Wallet-Based Age Verification for Third-Party Services
status: raw
category: Standards Track
tags: zero-knowledge, age-verification, privacy, anonymous-credentials, openac, alcohol-purchase
editor: Nicole Yeh <nicole@ethereum.org>
contributors:
  - Moven Tsai <moven.tsai@ethereum.org>
  - Nicole Yeh <nicole@ethereum.org>
  - Vivian Jeng <vivian.jeng@ethereum.org>
---

# Change Process

This document is governed by the process in [`process/`](https://github.com/ethereum/access-layer-specs/tree/main/process) of ethereum/access-layer-specs, which superseded [1/COSS](https://github.com/ethereum/access-layer-specs/tree/main/specs/1-coss).

# Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).

# Abstract

This specification defines an OpenAC-based privacy-preserving age-verification protocol for wallet-based proof presentation to third-party services.

In the MVP scope, the holder proves possession of a valid Driver License verifiable credential without disclosing raw identity attributes to the merchant.

For the MVP Driver License profile, age eligibility for alcohol purchase is satisfied by proof of possession of a valid Driver License credential under an accepted credential profile in the target deployment jurisdiction whose issuance policy requires the holder to be at least 18 years old.

The protocol adopts the OpenAC prepare-reblind-show model and includes device binding for each presentation. The verifier returns only a minimal eligibility result (`pass` / `fail`) plus metadata. Merchant integrations are verifier-service based, with a standalone verifier service or SDK-like integration kit. Passport-based age calculation is not in scope for this version.

# Motivation

Online alcohol purchase flows require age gating, while minimizing unnecessary disclosure of identity data to merchants.

This specification defines a primitive that separates age verification from raw identity disclosure by using an OpenAC-based zero-knowledge proof flow integrated with a wallet-based user experience.

# OpenAC Profile

This specification defines an application profile of OpenAC for age verification.

Conforming implementations MUST:

1. separate reusable credential preparation from per-presentation show proof generation,
2. support re-randomization / reblind of prepared state and linked proof material,
3. perform a fresh reblind step for each presentation before generating the presentation proof,
4. include device binding for each presentation, bound to the verifier's fresh session challenge, and
5. allow the verifier to validate consistency between the prepared-state relation and the show relation for the current presentation.

This version does not define:

- credential issuance flows,
- trust-anchor or allowlist management,
- revocation source, list location, or concrete revocation mechanism,
- wallet attestation lifecycle, or
- the underlying proving backend, commitment scheme, or exact public-input encoding.

These remain external to this specification or are to be defined in a future revision.

# Specification

## System Requirements

Implementations MUST provide:

### 1. Credential Model

The MVP credential in scope is a Driver License verifiable credential.

Implementations MUST support proof of credential validity / holder possession for an accepted Driver License credential profile.

For the MVP Driver License profile, `age >= 18` eligibility is satisfied by proving possession of a valid Driver License credential under an accepted credential profile in the target deployment jurisdiction whose issuance policy requires the holder to be at least 18 years old.

This version does not require:

- DOB disclosure,
- DOB-derived age computation, or
- a separately asserted `age >= 18` boolean field inside the credential.

Passport-based age calculation is not in scope for this version.

This version does not define the exact Driver License credential attribute schema. Implementations MUST use a credential profile whose authenticated payload is sufficient to support:

1. credential validity / holder possession, and
2. identification of the credential as an accepted Driver License profile for this verification flow.

### 2. Verification Session

The merchant backend MUST create a server-side verification session for each checkout attempt that requires alcohol-purchase eligibility verification.

A verification session MUST include:

- `session_id`
- `nonce`
- `request_uri` or an equivalent signed request object
- `expires_at`
- `purpose = alcohol_purchase`

The verifier MUST enforce:

- `nonce` uniqueness,
- single-use session semantics, and
- server-side expiry validation.

### 3. Presentation Request

The wallet MUST fetch the presentation request via `request_uri` or an equivalent request object reference.

The presentation request MUST carry the parameters required for wallet-side validation, including:

- `nonce`
- `aud`
- `purpose`
- `schema_version`
- `expires_at`

This version uses `purpose = alcohol_purchase`.

### 4. Wallet Request Validation

Before proof generation, the wallet MUST validate the presentation request.

The wallet MUST reject requests where any of the following checks fail:

- audience validation (`aud`)
- nonce presence / integrity
- `purpose == alcohol_purchase`
- `expires_at` has not been exceeded
- `schema_version` is supported

### 5. Credential Selection and Local Validation

The wallet MUST select a Driver License verifiable credential for this flow.

Before proof generation, the wallet MUST perform local validation checks and fail fast when these checks do not pass.

At minimum, local validation MUST include:

- format / schema sanity
- credential not expired

When revocation status is available, implementations SHOULD check it before proof generation.

This version requires revocation / invalidation handling, but the revocation source, list location, and concrete implementation mechanism are to be defined.

### 6. OpenAC Preparation and Re-randomization

The wallet MUST support a reusable OpenAC preparation step for the selected credential.

The preparation step MUST validate the credential under the integrated credential-verification profile and derive a prepared state sufficient for later presentation proofs.

Implementations MAY precompute batches of prepared states or batches of re-randomized prepared states for future presentations.

For each presentation, the wallet MUST:

1. select one prepared state associated with the credential, and
2. perform a fresh re-randomization / reblind step before generating the presentation proof.

Implementations MUST NOT treat a previously generated presentation transcript as valid for a later session.

The verifier MUST be able to validate consistency between the current presentation proof and the prepared-state relation used for that presentation.

### 7. Device Binding

Implementations MUST bind each presentation to a device-bound key and to the verifier's fresh session challenge.

Device binding MUST authorize the current presentation for the current session and MUST be checked as part of proof verification.

This version does not fix whether the device-bound key is held in a secure element or another protected key store, but deployments MUST document the device-key protection model they rely on.

### 8. Proof Statement

For `purpose = alcohol_purchase`, the prover MUST generate an OpenAC proof package bound to the active verification session showing that:

1. the prover possesses the selected Driver License credential,
2. the credential is valid under the integrated credential-verification profile,
3. the credential satisfies the accepted Driver License profile for this verification flow,
4. the presentation is linked to the prepared state and its fresh re-randomized / reblinded representation used for the current session,
5. the presentation is device-bound for the current session, and
6. the proof is bound to the verifier challenge and request context.

For the MVP Driver License profile, successful verification of items 1-5 satisfies the verifier's `age >= 18` eligibility requirement.

The proof MUST bind to:

- `nonce`
- `aud`
- `purpose`

### 9. Proof Submission

The wallet MUST submit the proof package to the verifier.

The submission MUST include:

- `session_id`
- a proof package sufficient to validate the prepared-state relation, the current show relation, their linkage, and device binding for the current presentation
- public inputs required for verification of session binding
- metadata required for versioning / proof interpretation

### 10. Merchant Result Model

The verifier MUST return only:

- a minimal eligibility decision (`pass` or `fail`), and
- non-PII metadata required for merchant operation.

The verifier MUST NOT return raw credential fields or other raw identity data to the merchant.

A minimal metadata set SHOULD include:

- `verified_at`
- `expires_at`
- `proof_type`
- `schema_version`
- `purpose`

### 11. Eligibility Scope

Merchant eligibility derived from a successful verification MUST be scoped to the current order / checkout session.

Merchant systems MUST NOT treat a successful alcohol-purchase verification as a permanent identity assertion.

## Protocol Flow

Implementations MUST support the following flow:

1. The user initiates an online alcohol purchase flow.
2. The merchant frontend requests the merchant backend to start verification.
3. The merchant backend creates a verification session and requests OpenAC verifier context.
4. OpenAC returns `session_id`, `nonce`, `request_uri` (or equivalent request object), and `expires_at`.
5. The merchant frontend displays a QR code or deep link to the wallet.
6. The wallet fetches the presentation request via `request_uri`.
7. The wallet validates request fields (`aud`, `nonce`, `purpose`, `schema_version`, `expires_at`).
8. The wallet selects a Driver License credential and performs local validation.
9. The wallet retrieves or constructs an OpenAC prepared state for the selected credential. If no prepared state exists, the wallet runs the preparation step. Implementations MAY already have precomputed prepared states offline.
10. The wallet selects one prepared state and performs a fresh re-randomization / reblind step for the current presentation.
11. The device authorizes the current presentation by signing the session challenge / nonce or by producing an equivalent device-bound authorization input.
12. The wallet generates the show proof over the re-randomized state, the request context, and the device-binding witness. For the MVP Driver License profile, this establishes age eligibility.
13. The wallet submits `proof package + public inputs + session_id` to the verifier.
14. The verifier validates the proof package, the prepared-state relation, the show relation, their linkage, device binding, session binding, and anti-replay conditions.
15. The verifier returns `pass` / `fail` plus allowed metadata to the merchant backend.
16. The merchant backend marks the current checkout as eligible or ineligible and continues the purchase flow accordingly.

## Circuit Design

This version defines the OpenAC proof pipeline and verification constraints, but does not fix the underlying proving backend, commitment scheme, or credential encoding profile.

### Relation Split

Implementations MUST realize the proof pipeline as two linked relations:

1. a prepare relation for reusable credential preparation, and
2. a show relation for the current presentation.

### Prepare Relation

The prepare relation is an offline or amortized relation associated with the selected credential.

#### Private Inputs

Private inputs to the prepare relation MUST be sufficient to prove:

- possession of the selected Driver License credential,
- credential validity under the integrated credential-verification profile, and
- construction of the prepared state used for later presentations.

#### Public Inputs

This version does not freeze the exact public inputs of the prepare relation.

Implementations MUST expose whatever public verification context is necessary for the verifier to validate the prepared-state relation for the current presentation.

#### Prepare Relation Operations

The prepare relation MUST enforce that:

1. the selected credential is valid under the integrated credential-verification profile,
2. the authenticated payload is parsed or normalized as required by that profile,
3. the credential is recognized as an accepted Driver License profile for this verification flow, and
4. a prepared state is constructed for later linkage to a presentation proof.

### Re-randomization / Reblind Step

From a prepared state, the wallet MUST derive a fresh presentation state for the current presentation.

The re-randomization / reblind step MUST refresh the hidden representation used by the presentation.

The verifier MUST be able to validate consistency between the show relation and the re-randomized prepared state used for that session.

This version does not freeze the exact linkage mechanism.

### Show Relation

The show relation is the online, per-presentation relation.

#### Private Inputs

Private inputs to the show relation MUST be sufficient to prove:

- linkage to the selected prepared state,
- compatibility with the accepted Driver License profile required for this verification flow, and
- device-bound authorization for the current session.

#### Public Inputs

Public inputs MUST be sufficient to verify session binding and request compatibility.

At minimum, the verifier MUST be able to validate consistency against:

- `nonce` (or an equivalent nonce-binding public value)
- `aud`
- `purpose`
- `schema_version`
- `expires_at`, when represented as part of the public verification context
- any public linkage material required by the integrated OpenAC profile

This version does not freeze the exact public-input encoding.

#### Show Relation Operations

The show relation MUST enforce the following claims for the active session:

1. **Credential profile compatibility**

   The presentation is linked to a Driver License credential profile accepted by the verifier for this verification flow.

   For the MVP Driver License profile, verifier age eligibility is derived from the accepted credential profile and its issuance policy, not from DOB disclosure or in-circuit age computation.

2. **Prepare / show linkage**

   The current presentation is linked to the prepared state associated with the credential and to the fresh re-randomized / reblinded state used in the current session.

3. **Device binding**

   The current presentation is authorized by a device-bound key for the verifier's fresh session challenge or equivalent authorization input.

4. **Session binding**

   The proof is bound to the verifier request context:

   - `nonce`
   - `aud`
   - `purpose = alcohol_purchase`

5. **Request compatibility**

   The proof is generated for a supported `schema_version`.

### Outputs

This version does not define raw disclosed outputs from the credential.

The verifier outcome exposed to the merchant is limited to:

- `pass` / `fail`
- allowed metadata only

## Proof Output Format

Implementations MUST serialize proof submissions in a deterministic format.

A minimal proof submission object SHOULD include:

```text
{
  session_id: <string>,
  proof: <bytes or proof package>,
  public_inputs: <implementation-defined>,
  metadata: {
    schema_version: <string>,
    proof_type: <string>,
    purpose: "alcohol_purchase"
  }
}
```

The `proof` field MUST contain sufficient material to verify the current OpenAC presentation, including the prepared-state relation, the current show relation, their linkage, and device binding.

A minimal verifier result object SHOULD include:

```text
{
  decision: "pass" | "fail",
  metadata: {
    verified_at: <timestamp>,
    expires_at: <timestamp>,
    proof_type: <string>,
    schema_version: <string>,
    purpose: "alcohol_purchase"
  }
}
```

## Proof Verification

### Verifier MUST

- validate the proof package and linked proof artifacts against the provided public inputs,
- validate the prepared-state relation and the show relation for the current presentation,
- validate prepare / show linkage for the current presentation,
- validate device binding for the verifier's fresh session challenge or equivalent authorization input,
- validate that `session_id` identifies an active verification session,
- validate that submitted public inputs match the active session context,
- validate `purpose == alcohol_purchase`,
- reject expired sessions / requests,
- enforce single-use semantics for the session / nonce,
- reject replayed submissions, and
- return only `pass` / `fail` plus allowed metadata to the merchant.

### Verifier SHOULD

- ensure the merchant-facing result contains no raw credential fields,
- maintain operational logging that is sufficient for debugging without storing raw identity data, and
- document the deployment's device-key protection model and accepted Driver License profile assumptions.

## Error Handling

Implementations MUST handle:

- request fetch failure,
- invalid request parameters,
- unsupported `schema_version`,
- malformed credential,
- expired credential,
- missing or invalid prepared state,
- re-randomization / reblind failure,
- missing or invalid device-binding authorization,
- proof generation failure,
- invalid proof package,
- invalid or expired session,
- session mismatch between submission and active verifier context, and
- replayed proof / replayed session.

Error responses SHOULD include:

- error code,
- error message, and
- error details, when available.

## Interoperability Constraints

- Implementations MUST use the same request semantics for `purpose`, `aud`, `nonce`, `schema_version`, and `expires_at`.
- Implementations MUST treat `purpose = alcohol_purchase` consistently across wallet, verifier, and merchant integration surfaces.
- Implementations MUST consistently interpret the accepted Driver License profile used to satisfy `age >= 18` for this flow.
- Implementations MUST consistently interpret the device-binding requirements of the integrated OpenAC profile.
- Implementations MUST ensure the merchant receives only `pass` / `fail` plus allowed metadata.
- Implementations MUST scope successful verification to the current order / checkout session.
- Request retrieval and proof submission MUST use HTTPS / TLS.

# Security Considerations

## Privacy and Data Minimization

The merchant MUST receive no raw identity data from the credential.

The merchant result is limited to:

- eligibility decision, and
- allowed metadata required for operational handling.

## Unlinkability and Re-randomization

Per-presentation unlinkability depends on fresh re-randomization / reblind of prepared state and linked proof material before each presentation.

Wallets MUST NOT reuse presentation artifacts across sessions.

If re-randomization is omitted, reused, or incorrectly implemented, colluding verifiers MAY be able to link presentations that should otherwise be unlinkable.

## Device Binding and Transfer Resistance

Device binding reduces credential sharing risk by binding the current presentation to a device-bound key and the verifier's fresh session challenge.

The strength of this protection depends on the protection model of the device-bound key.

If the device-bound key can be exported, duplicated, or replayed outside the intended device context, non-transferability is weakened.

## Anti-Replay

Replay resistance depends on the combination of:

- unique `session_id`,
- unique `nonce`,
- session expiry, and
- verifier-side single-use enforcement.

A verifier MUST reject:

- reused proofs for the same session,
- reused session / nonce submissions, and
- expired verification requests.

## Proof Integrity

Verifier implementations MUST reject:

- modified proofs,
- proofs whose public inputs do not match the active session,
- proofs generated for the wrong `purpose`, and
- presentations missing valid device binding.

## Revocation / Invalidation

Current planning requires local credential validation and notes revocation-status checks when available.

This version requires revocation / invalidation support, but does not yet standardize the revocation source, list location, implementation mechanism, or representation inside the proof. These items are to be defined.

## External Trust and Issuance Assumptions

For the MVP Driver License profile, verifier age eligibility depends on a deployment assumption: the accepted Driver License profile in the target deployment jurisdiction is issued only to holders aged 18 or older.

Trust-anchor selection, issuer allowlisting, and validation of jurisdiction-specific issuance policy are external to this specification and MUST be documented by deployments.

## Known Scope Limits

- Driver License is the only MVP credential in scope.
- Passport-based age calculation is out of scope for this version.
- DOB disclosure and DOB-derived age computation are out of scope for the MVP Driver License profile.
- The exact Driver License attribute schema is not defined in this version.
- The exact proving backend, commitment scheme, and public-input encoding are not fixed in this version.
- The revocation source, list location, and concrete revocation mechanism are to be defined.

# Implementation Notes

This specification is intended for:

- integration with a wallet / proof-generation UI,
- a standalone merchant verifier service or SDK-like integration kit, and
- merchant flows where checkout eligibility is determined by a privacy-preserving age-verification result.

The current implementation track includes:

- wallet integration in the TWDIW Official App,
- merchant-side session creation that returns `session_id`, `nonce`, `request_uri`, and `expires_at`,
- wallet-side request validation for `aud`, `purpose`, `expires_at`, and `schema_version`,
- wallet-side proof generation interfaces that accept challenge / audience / purpose inputs and return proof material, public inputs, and metadata, and
- verifier-side proof submission endpoints that accept `proof`, `public_inputs`, and `session_id`, and return a decision plus metadata.

Specific toolchains such as mobile native bindings, WASM verifier bindings, `mopro-ffi`, or NPM packaging are implementation choices and are not conformance requirements unless a future revision states otherwise.

# References

- [1/COSS](https://github.com/privacy-ethereum/zkspecs/tree/main/specs/1)
- [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt)
- [1/OPENAC](../1-openac/README.md)
- [OpenAC: Open Design for Transparent and Lightweight Anonymous Credentials](https://github.com/privacy-ethereum/zkID)
- [2/ZK-PROOF-OF-PERSONHOOD](../2-zk-proof-of-personhood/README.md)
- [TWDIW-integration](https://github.com/zkmopro/TWDIW-integration)
- [TWDIW Official App](https://github.com/moda-gov-tw/TWDIW-official-app)

# Glossary

**Accepted Driver License profile**
A Driver License credential profile that the verifier accepts for this verification flow. In the MVP deployment, possession of a valid credential in this profile is sufficient to satisfy the verifier's `age >= 18` policy.

**Device binding**
A proof component that binds the current presentation to a device-bound key and to the verifier's fresh session challenge.

**Prepare relation**
The reusable OpenAC relation that validates the credential under the integrated credential-verification profile and derives a prepared state for later presentations.

**Re-randomization / reblind**
The per-presentation refresh step that changes the hidden representation of the prepared state before the show proof is generated.

**Show relation**
The OpenAC relation executed for the current presentation, proving the current policy, session binding, prepare / show linkage, and device binding.

**Presentation request**
The verifier-generated request that the wallet retrieves through `request_uri` or an equivalent request object and validates before proof generation.

**Verification session**
The server-side state created for a single checkout attempt, including `session_id`, `nonce`, `purpose`, and expiry.

# Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).

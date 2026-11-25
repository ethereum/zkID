---
slug: 1
title: 1/OPENAC
name: OpenAC
status: raw
category: Standards Track
tags:
  - zero-knowledge
  - anonymous-credentials
  - sd-jwt
  - device-binding
editor: Nicole Yeh <Nicole.yeh@ethereum.org>
contributors:
  - Nicole Yeh <Nicole.yeh@ethereum.org>
  - Vikas Rushi <vikas.rushi@ethereum.org>
  - Vivian Plasencia <vivian.plasencia@ethereum.org>
---

# Change Process

This document is governed by the [1/COSS](https://github.com/privacy-ethereum/zkspecs/tree/main/specs/1) (COSS).

# Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).

# Abstract

This specification defines OpenAC Core, a two-phase anonymous-credential
presentation protocol with offline precomputation and online presentation.
OpenAC separates expensive credential validation work into a reusable
`Prepare` phase and executes policy evaluation and device binding in a
presentation-specific `Show` phase.

This raw version records a conservative OpenAC core surface: roles and trust
boundaries, `Prepare` / `Show` / linking semantics, verifier-facing proof
bundle handling, verifier requirements, and a current `SD-JWT-P256` profile.

This version does not yet standardize revocation, nullifiers, on-chain
verification, or non-SD-JWT credential profiles.

# Motivation

Anonymous-credential systems in deployment-oriented settings often face a
practical tradeoff:

- reuse existing issuer infrastructure and accept high proving latency per
  presentation; or
- redesign issuance formats and trust assumptions to obtain fast online proofs.

OpenAC aims to preserve existing issuer workflows while reducing presentation
latency. It does so by splitting the prover workflow into:

- a reusable offline step that validates the issuer-signed credential and binds
  shared witness data; and
- a lightweight online step that proves verifier-requested predicates and binds
  the presentation to a fresh verifier challenge.

The protocol is intended to give implementers a reviewable protocol surface
that is independent from any specific SDK or application.

# Specification

## Scope

This specification defines the OpenAC core presentation protocol and one
implementation profile.

This version specifies:

- a two-phase proving model consisting of `Prepare` and `Show`;
- a linking requirement that both proofs reference the same committed witness
  values;
- predicate and Boolean-expression encoding for the `Show` phase;
- presentation proof bundle serialization; and
- verifier behavior required to accept or reject a presentation.

This version does not specify:

- credential issuance protocols;
- revocation;
- nullifiers;
- cross-credential linking primitives;
- on-chain verifier interfaces;
- generalized predicate families beyond the primitive operators in this
  document; or
- profiles for `mdoc`, `X.509`, or other credential containers.

## Conformance

Conformance is defined at two layers:

- `Core conformance`: roles, trust boundaries, `Prepare` / `Show` semantics,
  linking, proof-bundle handling, and verifier behavior.
- `Profile conformance`: credential-container rules, claim normalization,
  challenge encoding, circuit parameterization, and any additional public
  outputs.

An implementation claiming OpenAC conformance MUST implement this core
specification together with at least one concrete profile.

A complete deployment also depends on requirements outside the scope of
this specification; these are addressed in [Layering](#layering) below as
`Deployment policy`.

## Layering

Each normative requirement in this specification belongs to exactly one of
three layers:

- `OPENAC` (core): protocol semantics that hold across all credential
  profiles — `Prepare` / `Show` structure, linking, proof-bundle handling,
  versioning semantics, and verifier responsibilities that do not depend
  on a credential container.
- `SD-JWT-P256` (profile): credential-format-specific requirements — JOSE
  validation, ECDSA encoding, claim normalization, challenge encoding,
  recommended circuit parameterization, and the Show circuit's public
  outputs.
- `Deployment policy` (policy): requirements that MUST be enforced by the
  verifier or deployment but that this specification does not normatively
  fix — issuer trust resolution, audience or origin binding, challenge
  replay storage, business authorization.

An implementation claiming OpenAC conformance MUST satisfy `OPENAC` and at
least one concrete profile. The implementation MUST also surface
`Deployment policy` inputs to the verifier and MUST fail closed when a
required policy input is missing. Where this specification cannot do so
because the relevant control is not yet implemented in the reference
SDK, the SDK SHOULD emit a verifier-visible warning identifying the
missing policy input.

## Roles

An OpenAC deployment involves the following roles:

- `Issuer`: signs a credential under an issuer-controlled signing key.
- `Holder`: controls a wallet that stores the credential and produces OpenAC
  proofs.
- `Device`: holds a device-binding signing key corresponding to a public key
  referenced by the credential.
- `Verifier`: supplies a fresh challenge, verification policy, and verification
  keys, and decides whether to accept the presentation.
- `Proving Backend`: an implementation component that constructs and verifies
  zero-knowledge proofs. It is not a trust role.

## Trust Boundaries

Implementations MUST make the following trust boundaries explicit:

- The verifier is responsible for challenge freshness and replay prevention.
- The verifier is responsible for selecting and authenticating the issuer
  public key or issuer allowlist used for acceptance.
- The holder is responsible for protecting credential contents and the
  device-binding private key.
- The proving backend MUST NOT be assumed trusted beyond correct execution of
  the chosen proving system.

## Terminology

For the purposes of this specification:

- `Prepare proof`: a proof of credential validity and shared-witness
  preparation that is independent of a single verifier challenge.
- `Show proof`: a proof of presentation policy satisfaction and device binding
  for a single verifier challenge.
- `Shared witness`: the secret values that MUST be identical across the
  `Prepare` and `Show` relations for a given presentation.
- `Normalized claim value`: a scalar value derived from credential content and
  consumed by the `Show` relation. The derivation procedure is profile-defined.
- `Predicate`: a primitive comparison over a normalized claim value.
- `Logic expression`: a postfix Boolean program over predicate results.

## Protocol Overview

The OpenAC holder workflow consists of four stages:

1. `Credential acquisition`
   The holder obtains an issuer-signed credential and stores or derives a
   device-binding key pair.
2. `Prepare`
   The holder validates the credential in zero knowledge and creates a reusable
   proof artifact tied to shared witness values.
3. `Show`
   For a verifier-supplied challenge and policy, the holder proves policy
   satisfaction and device binding while reusing the same shared witness.
4. `Verify`
   The verifier checks both proofs, checks their linking condition, validates
   challenge freshness, and applies the application policy.

## Cryptographic Primitives

This version of OpenAC Core requires the following primitives in the
`SD-JWT-P256` profile:

- `SHA-256` for hashing JWT signing inputs and verifier challenges.
- `ECDSA` over `P-256` for issuer signatures (`ES256`) and device-binding
  signatures.

The proof system is abstract at the protocol layer. An implementation MAY use
any proving backend that preserves the semantics in this specification.

The current reference implementation uses a transparent proof system and an
internal shared-commitment consistency check derived from the OpenAC paper.
That backend choice is informative for this raw specification and not yet a
normative interoperability requirement.

## Core Data Model

### Credential Input

For the current profile, the holder input MUST include:

- `jwt`: a compact JWS string with three base64url-encoded segments.
- `disclosures`: an ordered list of SD-JWT disclosures.
- `issuer_public_key`: a `P-256` issuer verification key in JWK or PEM form.

### Device Binding Key

The credential profile MUST define how the device public key is bound to the
credential.

In the `SD-JWT-P256` profile, the holder device public key is extracted from
`payload.cnf.jwk` and MUST be a `P-256` JWK with fields `kty`, `crv`, `x`, and
`y`.

### Verifier Challenge

The verifier challenge is an opaque byte string supplied out of band.

Profiles MUST define how applications serialize the challenge into bytes for
device signing and `Show`-relation inputs.

For the current profile:

- the application challenge is a string encoded as `UTF-8`;
- the holder device signs `SHA-256(UTF8(challenge))`;
- the `Show` relation consumes `messageHash =
  SHA-256(UTF8(challenge)) mod q_P256`, where `q_P256` is the `P-256` scalar
  order.

### Normalized Claim Values

The `Show` relation consumes a vector of normalized claim values.

This specification requires that:

- normalized claim values MUST be deterministic for a given credential and
  profile;
- each value MUST fit in the circuit parameterization used by the profile; and
- the same values MUST be used in both the holder and verifier reasoning about
  the presentation.

This raw version does not yet standardize a general normalization framework.
Profiles MUST define the normalization rules they rely on.

## SD-JWT-P256 Profile

This section defines the credential profile currently reflected by the
reference implementation.

### Credential Form

The credential MUST be a compact JWS:

```text
BASE64URL(header) || "." || BASE64URL(payload) || "." || BASE64URL(signature)
```

### JOSE Header and Issuer Trust

The JOSE header MUST satisfy all of the following:

- `alg = ES256`. Any other algorithm MUST be rejected.
- `alg = none` MUST be rejected unconditionally.
- Unknown `crit` header parameters MUST cause rejection.
- If `kid` is present, the verifier MUST resolve it through an explicit
  issuer-key resolver. Verifiers MUST NOT accept arbitrary issuer public
  keys without resolving them against a deployment-controlled trust set.

Binding the resolved issuer key to the credential `iss` value and to the
credential type is a `Deployment policy` responsibility (see
[Verifier Requirements](#verifier-requirements)).

### ECDSA Signature Encoding

Within this profile, all `P-256` signatures — both the issuer JWT
signature and the device-binding signature on the verifier challenge —
MUST be encoded as fixed-width raw `r || s`, 32 bytes each, big-endian.
DER-encoded signatures MUST be rejected.

Device-binding signatures MUST be low-S. Implementations MUST reject
high-S device-binding signatures to ensure verifier and circuit behavior
agree on which presentations are valid.

Issuer signatures MAY be accepted in either low-S or high-S form for
compatibility with existing issuer infrastructure, but the verifier MUST
apply the same rule the circuit applies.

### Disclosures

Each disclosure MUST be a base64url string that decodes to a JSON array:

```json
["salt", "claim_name", "claim_value"]
```

For this profile, the disclosure digest is:

```text
BASE64URL( SHA-256( raw_disclosure_string ) )
```

The hash MUST be computed over the exact raw disclosure string bytes
provided by the issuer. JSON reserialization before hashing is forbidden.

The profile requires that disclosed claims used by OpenAC be consistent
with the SD-JWT payload commitment structure.

Additional disclosure rules for this profile:

- Disclosures with identical `claim_name` MAY appear in the same
  credential. A duplicate `claim_name` value MUST NOT by itself cause
  rejection.
- Disclosures MUST be presented in a deterministic order fixed by the
  issuer. Verifiers MUST treat disclosure order as significant for
  matching disclosures to profile-defined claim slots.
- Disclosure order MUST NOT affect the digest of an individual
  disclosure (each digest is over its own raw string).
- The mapping of disclosed claims to the `Show` relation's claim slots is
  a verifier-side concern: the verifier knows the credential format and
  resolves claim names to slots directly. This specification does not
  define a normative slot-name registry.

### Challenge Encoding

This profile defines three challenge-related values:

```text
challenge_bytes  := the verifier-provided challenge as UTF-8 bytes
challenge_digest := SHA-256(challenge_bytes)
challenge_scalar := OS2IP(challenge_digest) mod q_P256
```

`challenge_scalar` is the in-circuit field-element encoding consumed by
the `Show` relation. It MUST NOT be interpreted as the message that
external ECDSA libraries sign or verify.

`challenge_bytes` (or a deployment-defined transformation thereof) is the
message signed by the device-binding key.

Verifiers MUST require the same challenge encoding pipeline as the
circuit. Replay prevention and audience/origin binding are `Deployment
policy` responsibilities (see [Verifier Requirements](#verifier-requirements)).

### Device Binding Key Location

The device-binding public key MUST be stored in:

```text
payload.cnf.jwk
```

and MUST encode a `P-256` public key.

### Profile-Specific Claim Normalization

This profile defines a local `claimFormats` vector aligned with the
profile-selected claim slots used during `Prepare`.

The current `SD-JWT-P256` profile assigns the following format tags:

- `0 = bool`
- `1 = uint`
- `2 = iso_date`
- `3 = roc_date`
- `4 = string`

Normalization rules are:

- `bool`: normalize `"1"` or `"true"` to `1`; all other accepted values
  normalize to `0`.
- `uint`: parse decimal ASCII digits as an unsigned integer.
- `iso_date`: parse `YYYY-MM-DD` into the integer `YYYYMMDD`.
- `roc_date`: parse `YYYMMDD` into the integer with the same decimal digits.
- `string`: pack up to 8 ASCII bytes big-endian into a single scalar.

Inactive claim slots normalize to `0`.

Implementations MUST reject claim values that fail their declared format:

- `bool`: any value other than the recognized truthy or falsy encodings.
- `uint`: empty strings, non-decimal characters, leading whitespace, or
  values exceeding the active `valueBits` range.
- `iso_date`: values that do not match the exact `YYYY-MM-DD` lexical
  form, or that resolve to an invalid calendar date.
- `roc_date`: values that do not match the exact `YYYMMDD` lexical form.
- `string`: inputs that do not fit within 8 ASCII bytes once packed, or
  that contain disallowed bytes.

These tags are profile-specific. They do not establish a cross-profile
normalization registry for OpenAC Core.

### Show Public Outputs

In this profile, the `Show` circuit MUST emit exactly the following
verifier-observable public output:

- `expression_result`: the Boolean result of the policy expression
  (required by Core).

The device-binding public key MUST NOT appear in the `Show` circuit's
verifier-observable public values. The binding between the device key
extracted in `Prepare` and the device-binding signature verified in
`Show` is enforced by the shared-witness commitment equality between
the two relations (see [Linking Requirement](#linking-requirement)).
The shared-witness commitment is hiding and re-randomized per
presentation, so the verifier is convinced that the same device key
was used in both relations without observing a stable identifier
across sessions.

Note: the issuer still learns the device↔credential association from
`payload.cnf.jwk` in the SD-JWT cleartext. The `Show` public-value rule
above closes the verifier-side linkability surface but does not change
issuer-side linkability.

## Prepare Relation

The `Prepare` relation proves facts about the issuer-signed credential that do
not depend on a specific verifier session.

At a minimum, a conforming `Prepare` relation for the `SD-JWT-P256` profile
MUST prove the following statement:

1. The credential parses as a compact JWS.
2. The issuer signature verifies under the selected issuer public key.
3. The credential contains a valid device-binding public key according to the
   profile.
4. The disclosed-claim commitments used by the profile are consistent with the
   disclosed values provided by the holder.
5. The shared witness values required by the `Show` relation are bound into the
   proof state in a way that supports later linkage.

The `Prepare` relation MAY additionally derive normalized claim values for use
by the `Show` relation.

## Show Relation

The `Show` relation proves a presentation-specific statement tied to a verifier
challenge and policy.

A conforming `Show` relation MUST prove the following statement:

1. The holder knows the shared witness values linked to the corresponding
   `Prepare` proof.
2. The device-binding signature on the verifier challenge verifies under the
   device public key bound by the credential profile.
3. Each requested primitive predicate is evaluated over the specified
   normalized claim values.
4. The supplied postfix Boolean expression is evaluated over the primitive
   predicate results.

The `Show` relation MUST expose, either directly or through verifier-observable
public outputs, at least:

- `expression_result`: the Boolean result of the policy expression.

Profiles MAY define additional verifier-observable public outputs.
Such outputs MUST NOT expose a stable holder identifier — including a
stable device-binding public key — unless the profile explicitly accepts
the resulting linkability tradeoff.

## Linking Requirement

For every accepted presentation, the verifier MUST be convinced that the
accepted `Prepare` proof and accepted `Show` proof refer to the same shared
witness values.

This specification does not yet mandate a single linking construction.
However, an implementation MUST satisfy all of the following:

- linking MUST be binding, meaning a holder cannot combine a `Prepare` proof
  for one witness with a `Show` proof for a different witness;
- linking MUST be verified as part of presentation verification;
- linking failure MUST cause the overall presentation to be rejected.

The current reference implementation performs this check internally during
verification using a shared commitment consistency test.

## Versioning

Protocol versioning is distinct from SDK versioning.

This specification assigns the serialized `version` field the following
semantics:

- it identifies the proof-bundle or profile semantics expected by the verifier;
- it is bound by deployment policy to specific verification keys and circuit
  parameters; and
- it MUST NOT be interpreted as the holder application's software version.

A conforming verifier MUST bind each accepted `version` value to a tuple
fixing all of the following:

- `prepare` and `show` verifying keys;
- circuit parameter set (see [Recommended Circuit Parameters](#recommended-circuit-parameters));
- profile identifier (e.g. `SD-JWT-P256`);
- claim normalization rules in effect for that profile;
- challenge encoding pipeline (see [Challenge Encoding](#challenge-encoding));
- public-input layout for both relations.

Any change to a member of this tuple MUST be reflected as a new
`version` identifier. Verifiers MUST reject presentations whose
`version` is not explicitly bound to a known tuple under local policy.

The current `openac-sdk` implementation writes its SDK semantic-version string
into this field. This specification treats that behavior as a legacy
compatibility artifact rather than the normative long-term meaning of the
field.

## Predicate Encoding

This version defines three primitive predicate operators:

- `LE = 0`: less-than-or-equal comparison.
- `GE = 1`: greater-than-or-equal comparison.
- `EQ = 2`: equality comparison.

Each predicate is encoded as:

- `claimRef`: the zero-based index of the normalized claim value consumed by
  the predicate;
- `op`: one of the operator codes above;
- `compareValue`: the scalar comparison target.

Comparisons are unsigned bounded-integer comparisons over `valueBits`
(see [Recommended Circuit Parameters](#recommended-circuit-parameters)).
Implementations MUST reject a predicate if any of the following holds:

- `compareValue` is negative;
- `compareValue >= 2^valueBits`;
- the active `claimRef` value falls outside `[0, 2^valueBits)`;
- the `(op, claimFormat)` pair is not supported by this profile (for
  example, `LE` over a `string` claim).

## Logic Expression Encoding

Boolean composition of predicates uses postfix notation.

The token types are:

- `REF = 0`: push the result of predicate `value`.
- `AND = 1`: pop two Boolean values and push their conjunction.
- `OR = 2`: pop two Boolean values and push their disjunction.
- `NOT = 3`: pop one Boolean value and push its negation.

A logic expression is valid if and only if:

- every `REF` token refers to a predicate index in range;
- every operator has sufficient stack inputs;
- evaluation terminates with exactly one Boolean value on the stack.

Implementations MUST reject malformed logic expressions.

## Recommended Circuit Parameters

This raw version records the current reference implementation defaults for the
`SD-JWT-P256` profile:

### Prepare Defaults

- `maxMessageLength = 1920`
- `maxB64PayloadLength = 1900`
- `maxMatches = 4`
- `maxSubstringLength = 50`
- `maxClaimLength = 128`

### Show Defaults

- `nClaims = 2`
- `maxPredicates = 2`
- `maxLogicTokens = 8`
- `valueBits = 64`

Profiles MAY define other parameter sets, but interoperable deployments MUST
agree on the parameterization and verification keys used.

## Protocol Flow

### 1. Prepare

The holder MUST:

1. Parse the credential and disclosures.
2. Select or validate the issuer public key.
3. Extract the device-binding public key from the profile-defined location.
4. Build the `Prepare` relation inputs.
5. Produce and store:
   - `prepareProof`
   - `prepareInstance`
   - any local proving state required to later produce a linked `Show` proof

The cached `Prepare` state is holder-local and is not standardized as a network
object by this specification.

### 2. Show / Present

For each presentation, the verifier MUST provide a fresh challenge.

The holder MUST:

1. Obtain the verifier challenge.
2. Determine the normalized claim values required by the requested policy.
3. Produce a device-binding signature over the challenge.
4. Build the `Show` relation inputs, including:
   - normalized claim values
   - primitive predicates
   - logic expression tokens
5. Produce a `Show` proof linked to the selected `Prepare` state.
6. Return a presentation proof bundle to the verifier.

### 3. Verify

Upon receiving a presentation proof bundle, the verifier MUST:

1. Deserialize the bundle.
2. Verify the `Prepare` proof under the agreed `prepare` verification key.
3. Verify the `Show` proof under the agreed `show` verification key.
4. Verify the linking condition between them.
5. Validate challenge freshness and replay policy out of band.
6. Apply application policy to the `expression_result`.

## Presentation Proof Bundle

### Binary Serialization

The current profile defines a binary proof bundle consisting of five
length-prefixed byte strings in the following order:

1. `version`
2. `prepareProof`
3. `showProof`
4. `prepareInstance`
5. `showInstance`

Each element is encoded as:

```text
uint32_le length || raw_bytes
```

where `uint32_le` is a 32-bit unsigned little-endian integer.

The `version` field is encoded as UTF-8 bytes.
It identifies the accepted proof-bundle or profile version, not the SDK
release number.

### JSON Convenience Form

Implementations MAY expose a JSON convenience form containing:

```json
{
  "version": "string",
  "prepareProof": "base64",
  "showProof": "base64",
  "prepareInstance": "base64",
  "showInstance": "base64",
  "publicValues": {
    "expressionResult": true
  }
}
```

The JSON form is informative and does not replace binary verification inputs.

## Verifier Requirements

A conforming verifier MUST reject the presentation if any of the following
holds:

- the proof bundle cannot be deserialized;
- the `version` field is unsupported or does not match local profile policy;
- the `Prepare` proof is invalid;
- the `Show` proof is invalid;
- the linking condition fails;
- the challenge is expired, missing, or fails verifier replay policy;
- the verification keys or profile parameters do not match local policy.

A conforming verifier MUST distinguish between:

- `proof validity`: whether the cryptographic objects verify; and
- `policy acceptance`: whether `expression_result` is acceptable for the
  application.

For authorization decisions, the verifier MUST require `expression_result = 1`.

### Challenge Freshness and Replay

Every presentation MUST be evaluated against a verifier-supplied challenge
that satisfies the following profile minimums:

- the challenge MUST carry at least 128 bits of unpredictable entropy;
- each issued challenge MUST be single-use.

The following are `Deployment policy` responsibilities and MUST be
configured before a deployment is treated as conforming:

- bounded challenge time-to-live (TTL);
- a replay cache scoped by verifier identity, profile, and nonce;
- enforcement that an accepted challenge is removed from the issuable
  pool before the corresponding presentation is accepted.

### Audience Binding

A conforming verifier MUST bind each challenge to an audience scope so
that a presentation produced for one verifier cannot be relayed to a
different verifier. The audience scope MAY be a verifier identity,
origin, session identifier, or policy hash, as established by deployment
policy.

The reference SDK does not currently enforce audience binding. Until the
control is implemented, the SDK MUST emit a verifier-visible warning that
identifies the missing audience input, and deployments MUST either
provide audience binding via a higher-layer transport (such as a
challenge wrapper signed by the verifier) or accept the documented
relay risk.

### Issuer Trust Resolution

Issuer key resolution, issuer allowlist management, and binding of
issuer keys to credential `iss` values are `Deployment policy`
responsibilities. The verifier MUST provide an explicit issuer-key
resolver to the SDK. The SDK MUST refuse to verify presentations whose
resolver returns no trusted key.

## Error Handling

Implementations SHOULD expose failure causes that distinguish at least:

- malformed credential input;
- malformed disclosure input;
- unsupported key type;
- issuer signature failure;
- device signature failure;
- parameter limit exceeded;
- malformed logic expression;
- proof deserialization failure;
- proof verification failure;
- linking failure.

## Conformance Test Vectors

A conforming implementation of this profile SHOULD ship a verifier
conformance suite covering the following negative cases. The suite makes
verifier-profile behavior testable rather than implicit, and downstream
integrators MAY rely on it to confirm fail-closed behavior.

Each case lists a malformed or out-of-policy input and the expected
verifier outcome.

| Input | Expected outcome |
| --- | --- |
| Credential header `alg = none` | rejected: unsupported algorithm |
| Credential header `alg` other than `ES256` | rejected: unsupported algorithm |
| Credential header `kid` not resolvable by issuer resolver | rejected: unknown issuer key |
| Resolved issuer key does not match credential `iss` per policy | rejected: issuer binding failure |
| Replayed or stale single-use challenge | rejected: replay / TTL policy |
| Challenge bound to a different audience than the verifier | rejected: audience mismatch |
| DER-encoded device-binding signature | rejected: signature encoding |
| High-S device-binding signature | rejected: malleability policy |
| Duplicate disclosure (identical raw disclosure bytes) | rejected: duplicate disclosure |
| Disclosure order altered relative to issuer-fixed order | rejected: order mismatch |
| `iso_date` claim not matching `YYYY-MM-DD` | rejected: normalization failure |
| `uint` claim with non-decimal characters or leading whitespace | rejected: normalization failure |
| `string` claim exceeding 8-byte packing budget | rejected: normalization failure |
| Predicate with negative `compareValue` | rejected: compareValue range |
| Predicate with `compareValue >= 2^valueBits` | rejected: compareValue range |
| Unsupported `(op, claimFormat)` pair (e.g. `LE` over `string`) | rejected: operator unsupported |
| Presentation `version` not bound to any known verifier tuple | rejected: version policy |

These cases are normative for the SDK's validation layer; the layer MUST
return distinguishable error reasons consistent with
[Error Handling](#error-handling) above. The full corpus of test vectors
will be published as a separate artifact and referenced from
[`SOURCE-MATRIX.md`](./SOURCE-MATRIX.md) when available.

## Security Considerations

### Challenge Encoding

Challenge encoding is security-critical.

Implementations MUST ensure that the exact verifier challenge bytes used for
device signing are the challenge bytes to which the verifier expects the proof
to be bound.

### Shared-Witness Binding

Security of the two-phase construction depends on the soundness of the linking
condition. A verifier that checks the two proofs independently but does not
check linking is not conformant.

### Privacy and Linkability

A profile MUST NOT expose a stable device-binding public key as a
verifier-observable output. In `SD-JWT-P256`, the shared-witness
commitment equality between `Prepare` and `Show` binds the device key
used in `Prepare` to the device-binding signature verified in `Show`
without exposing a stable identifier across sessions; see
[Show Public Outputs](#show-public-outputs).

Implementers MUST treat any future addition of stable device-derived
public values as a privacy regression: such values let a verifier link
presentations at the application layer regardless of how freshly the
zero-knowledge transcripts are randomized.

The issuer continues to learn the device↔credential association from
the SD-JWT cleartext (`payload.cnf.jwk`). Eliminating verifier-side
linkability does not eliminate issuer-side linkability.

Verifiers and profiles SHOULD avoid making stable holder-derived
identifiers semantically required unless the deployment explicitly
accepts that privacy tradeoff.

### Local Proof Generation

Credential contents and device private keys are sensitive. Proof generation
SHOULD occur on the holder-controlled device whenever feasible.

## Extension Points

Future specifications MAY define:

- revocation extensions;
- nullifier extensions;
- generalized predicate and cross-credential composition;
- additional credential container profiles such as `mdoc` and `X.509`;
- alternative verifier interfaces, including on-chain variants; and
- a normalized claim-format registry.

## Implementation Status

This raw specification is based on the current
[OpenAC whitepaper](https://github.com/privacy-ethereum/zkID/tree/main/paper)
and the reference
[openac-sdk](https://github.com/privacy-ethereum/zkID/tree/main/wallet-unit-poc/openac-sdk)
implementation. It remains intentionally conservative, but now resolves the
main protocol-shape questions by:

- keeping core scope narrow;
- treating device-key exposure as a current implementation privacy caveat
  rather than a required core semantic;
- separating protocol/profile versioning from SDK versioning; and
- standardizing the currently visible `SD-JWT-P256` normalization tags without
  creating a cross-profile registry.

Remaining work before status promotion is primarily editorial and conformance-
oriented: assign a responsible editor, publish fixtures and test vectors, and
confirm the initial accepted `version` identifiers used by interoperable
deployments.

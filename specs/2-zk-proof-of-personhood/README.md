---
slug: 2
title: 2/ZK-PROOF-OF-PERSONHOOD
name: ZK-based Proof of Personhood for Online Forums
status: raw
category: Standards Track
tags: zero-knowledge, identity, privacy, anonymous-credentials, proof-of-personhood
editor: Nicole <nicole@ethereum.org>
contributors:
  - Moven <moven.tsai@ethereum.org>
  - Nicole <nicole@ethereum.org>
  - Vivian <vivian.jeng@ethereum.org>
---

# Change Process

This document is governed by the process in [`process/`](https://github.com/ethereum/access-layer-specs/tree/main/process) of ethereum/access-layer-specs, which superseded [1/COSS](https://github.com/ethereum/access-layer-specs/tree/main/specs/1-coss).

# Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).

# Abstract

This specification defines a privacy-preserving protocol that allows a user to prove possession of a valid issuer-signed certificate and obtain a one-time "verified personhood" status on an online forum without disclosing certificate attributes.

The protocol prevents duplicate verification via a deterministic nullifier. Off-chain verification is the deployment mode for this version. On-chain verification was evaluated and is deferred (see [On-Chain Verification Status](#on-chain-verification-status)).

The proof generation pipeline builds on OpenAC ([paper](https://github.com/privacy-ethereum/zkID/blob/main/paper/zkID.pdf)), adopting a minimal profile: X.509 certificate chain validation and proof-of-possession of the end-entity's private key, nullifier-based duplicate prevention, non-membership proof against the revocation list (currently a Sparse Merkle Tree; leanIMT+ is being evaluated for a future revision), and per-session blinded key commitments that link the two sub-circuits. The proof pipeline is split into two linked sub-circuits — a CertChain circuit for credential verification and a DeviceSig circuit for session binding and nullifier derivation.

This version (v0.1) enforces one verification per certificate instance. If the certificate is periodically renewed and renewal modifies the certificate contents, the user MAY be able to verify again (known limitation).

# Motivation

Online forums often require personhood verification to reduce Sybil attacks and automated abuse. Traditional verification methods require revealing personal information to the platform.

This specification defines a primitive that separates eligibility verification (possession of a valid certificate) from identity disclosure by using a zero-knowledge proof.

# Specification

## System Requirements

Implementations MUST provide:

### 1. Certificate Model

A certificate `S` is an X.509 certificate containing a serial number (`sn`), attributes `m`, and an RSA signature `σ` over the TBS (To-Be-Signed) certificate data.

- `sn` (serial number): The certificate's X.509 serial number, used as the key for revocation lookups. The `sn` does not directly reveal the prover's identity.

The certificate MUST be issued by a trusted Certificate Authority (CA). The issuer's public key `PK_I` MUST be verifiable through a certificate chain rooted in one of:
- hardcoded trusted CA root certificates (e.g., government root CA), or
- a platform-managed CA allowlist.

The certificate chain consists of:
- `PK_CA`: The public key from the intermediate CA certificate, which signs the end-entity certificate.
- `PK_I`: The issuer (root CA) public key, which signs the intermediate CA certificate.

Implementations MUST validate that the end-entity certificate was signed by a trusted CA public key.

### 2. Revocation List

The protocol MUST support certificate revocation via a **non-inclusion proof** against a revocation accumulator.

A revocation list is maintained as a **Sparse Merkle Tree (SMT)** where each leaf corresponds to a revoked certificate identifier:

```
revoked_leaf := Poseidon(sn, 1, 1)   // Hash3(key, value, entryMark)
```

A trusted party (e.g., the CA or a designated updater) MUST maintain and publish the full SMT, constructed from the CA's Certificate Revocation List (CRL) or an equivalent revocation feed. The published SMT state MUST be periodically rebuilt from the latest CRL. Only the SMT root (`revocation_root`) needs to be distributed for verification; the full tree state is distributed as a downloadable snapshot for client-side proof generation.

#### Witness Retrieval

To preserve privacy, the prover MUST generate the revocation non-inclusion witness locally. The prover MUST NOT send their `sn` to a remote service for witness retrieval.

The client-side witness retrieval flow is:

1. Download the compressed SMT snapshot to the local device.
2. Import the snapshot into a local disk-backed SMT (e.g., SQLite).
3. Generate the non-membership Merkle path (sibling hashes) for the prover's `sn` position locally.
4. Use the locally generated Merkle path as the `revocation_witness` private input. The CertChain circuit enforces consistency by verifying the SMT non-inclusion proof against the `smtRoot` public input, so the verifier checks the root match — the prover does not need to perform a separate root-comparison step.

The `sn` MUST NOT leave the prover's device during this process.

Implementations MUST support an off-chain revocation root distributed by the CA or a trusted updater (e.g., derived from a CRL). The snapshot distribution mechanism is implementation-defined (e.g., CDN, IPFS, or a public repository).

### 3. Challenge (Anti-replay)

Verifiers MUST provide a 256-bit `challenge` value per verification attempt.

- Challenges MUST be unpredictable.
- Challenges MUST expire (implementation-defined).
- Verifiers MUST reject proofs bound to expired challenges.

### 4. Nullifier

The protocol MUST output a deterministic nullifier to prevent duplicate verification.

The nullifier is derived from the card's RSA signature over the application identifier:

```
nullifier := Poseidon( RSA_Sign_sk(app_id) )
```

Where:
- `RSA_Sign_sk` is the card's RSA signing operation using the user's private key `sk` (PKCS#1 v1.5, which is deterministic — same key + same message = same signature),
- `app_id` is a platform identifier (domain separator),
- `Poseidon` is the Poseidon hash function (see [Cryptographic Primitives](#cryptographic-primitives)).

The nullifier is computed in the DeviceSig circuit, not the CertChain circuit (see [Circuit Design](#circuit-design)).

Because the nullifier derivation requires the card's private key, an adversary cannot compute nullifiers without possession of the card.

Each platform MUST use a unique `app_id`.

A future version SHOULD add a domain-separation tag to the signed message (e.g., `"zkID-nullifier-v1" || app_id`) to prevent cross-protocol nullifier correlation when the same card key is used across multiple ZK protocols.

## Cryptographic Primitives

This specification defines:

- Hash function (data integrity): `SHA-256` for certificate TBS data hashing.
- Hash function (nullifier, pk_commit): `Poseidon` hash over the secq256r1 scalar field, a ZK-friendly hash function optimized for arithmetic circuits. For hashing more than 16 field elements, implementations use `ChunkedPoseidonP256(N)` — a sponge construction wrapping `PoseidonP256(2)` that processes N field elements in chunks.
- Signature verification: `RSA_Verify(PK, msg, σ) -> {0,1}` — RSA signature verification over SHA-256 hashed TBS data.
- Sparse Merkle Tree non-inclusion: `SMT_NonInclusion(root, leaf, proof) -> {0,1}` — verifies that `leaf` is **not** present in the SMT committed to by `root` (see [PSE: Revocation in zkID](https://pse.dev/blog/revocation-in-zkid-merkle-tree-based-approaches)).
- Encoding: `Encode()` is a deterministic canonical encoding function using base64 encoding. All implementations MUST use the same base64 encoding variant (standard alphabet, with padding) to ensure consistent nullifier derivation across verifiers.

Concatenation MUST be length-prefixed (e.g., `len(x)||x||len(y)||y||...`) to avoid ambiguity.

## Recommended Parameters

### RSA

- Issuer CA key size: RSA-2048 or RSA-4096 (depending on certificate generation)
- User key size: RSA-2048
- Padding scheme: PKCS#1 v1.5
- Hash algorithm: SHA-256
- Maximum certificate length: 1536 bytes (24 SHA-256 blocks)

### Poseidon Hash

- Implementation: Poseidon over the secq256r1 scalar field (P-256 companion curve).
- Implementations MUST use round constants generated for the secq256r1 field.
- Implementations MUST use consistent round parameters (t, number of full/partial rounds) across all parties.

### Proving System

- Spartan2 with Hyrax polynomial commitment scheme. This is a transparent proving system (no trusted setup required).

On-chain verification is not supported in this version. See [On-Chain Verification Status](#on-chain-verification-status) for the research summary and rationale.

## Protocol Flow

Implementations MUST:

1. Obtain `challenge` and `app_id` from the verifier's challenge issuance endpoint and the current `revocation_root` from the verifier's revocation root status endpoint (see [Verifier API](#verifier-api)).
2. Download the SMT snapshot and generate the revocation non-inclusion witness locally (see [Witness Retrieval](#witness-retrieval)).
3. Generate fresh `pk_blind` (248-bit randomness) for this session.
4. Sign the TBS data (containing `app_id`) with the card's RSA key to obtain `σ_device`.
5. Construct CertChain circuit inputs from the issuer and user certificates, `pk_blind`, and the locally generated revocation witness.
6. Construct DeviceSig circuit inputs from the TBS data, `σ_device`, user public key, `pk_blind`, and the `challenge`.
7. Generate proofs for both circuits (see [Circuit Design](#circuit-design)).
8. Submit both proofs and their public inputs to the verifier.

## Circuit Design

The proof pipeline is split into two linked sub-circuits: a **CertChain** circuit for credential verification and a **DeviceSig** circuit for session binding and nullifier derivation.

### Relation Split

Implementations MUST realize the proof pipeline as two linked circuits:

1. **CertChain**: Verifies the certificate chain, checks revocation non-inclusion, extracts identity fields, and computes a blinded key commitment (`pk_commit`).
2. **DeviceSig**: Verifies the card's RSA signature over the session TBS data, derives the nullifier, binds to the session challenge and `app_id`, and computes the same `pk_commit`.

The two circuits are linked via `pk_commit`:

```
pk_commit := ChunkedPoseidonP256(user_pk_limbs[0..k] || pk_blind)
```

Where:
- `user_pk_limbs` are the limbs of the user's RSA-2048 public key (`k=17` limbs),
- `pk_blind` is fresh 248-bit randomness generated per session. 248 bits leaves headroom below the secq256r1 scalar field size and avoids overflow in `pk_commit` derivation.

Both circuits MUST compute `pk_commit` identically. The verifier MUST assert that the `pk_commit` from the CertChain proof equals the `pk_commit` from the DeviceSig proof.

`pk_blind` plays two roles:

1. **Cross-circuit linkage of the same user key.** The CertChain circuit and the DeviceSig circuit both consume the same `pk_blind` to compute identical `pk_commit` values, proving that both proofs reference the same underlying user public key without revealing the key itself.
2. **Blinding of the user public key.** Even if the user's RSA public key were leaked, an adversary could not reproduce `pk_commit` for a given session without also possessing the per-session `pk_blind`. The blinding value MUST be fresh per session; reusing `pk_blind` across sessions would allow the verifier to link presentations.

### Valid Configurations

Exactly two configurations are supported, depending on the issuer CA key size:

- **MOICA-G2**: `cert_chain_rs2048` + `device_sig_rs2048`
- **MOICA-G3**: `cert_chain_rs4096` + `device_sig_rs2048`

The DeviceSig circuit is always RSA-2048 because user keys are always RSA-2048.

### CertChain Circuit

#### Private Inputs

- `issuer_cert`: The issuer CA certificate (full structure, including the signature `σ` over the TBS certificate data and the issuer modulus).
- `user_cert`: The end-entity certificate (full structure, including the user's public key and serial number).
- `pk_blind`: Fresh 248-bit randomness for `pk_commit` blinding.
- `revocation_witness`: SMT non-inclusion proof (Merkle path of sibling hashes) for the prover's `sn`, generated locally from a downloaded SMT snapshot (see [Witness Retrieval](#witness-retrieval)).

The user serial number `sn` and user public-key limbs `user_pk_limbs` are extracted from `user_cert` in-circuit. The issuer modulus and issuer signature are extracted from `issuer_cert` in-circuit.

#### Public Inputs

- `pk_commit`: Blinded commitment to the user's public key.
- `modulus[N]`: Issuer CA RSA modulus limbs (N=17 for RSA-2048, N=34 for RSA-4096).
- `smtRoot: bytes32`: Current root of the revocation Sparse Merkle Tree.

#### CertChain Operations

The CertChain circuit MUST enforce:

1. **Certificate chain validation**

   Confirm that the end-entity certificate was issued by a trusted CA:

   ```
   isValid := RSA_Verify(issuer_modulus, TBS(user_cert), σ)
   assert(isValid == 1)
   ```

2. **Serial number extraction**

   ```
   sn := ExtractSerialNumber(user_cert)
   ```

3. **Non-inclusion of the revocation list**

   Prove the certificate has not been revoked:

   ```
   revoked_id := Poseidon(sn, 1, 1)   // Hash3(key, value, entryMark)
   assert( SMT_NonInclusion(smtRoot, revoked_id, revocation_witness) == 1 )
   ```

4. **pk_commit computation**

   ```
   pk_commit := ChunkedPoseidonP256(user_pk_limbs || pk_blind)
   ```

### DeviceSig Circuit

#### Private Inputs

- `TBS`: To-Be-Signed data for the device/credential signature.
- `σ_device`: RSA signature from the user's card over the TBS data.
- `user_pk_limbs`: Limbs of the user's RSA-2048 public key.
- `pk_blind`: Same per-session randomness used in the CertChain circuit.

#### Public Inputs

- `pk_commit`: Blinded commitment to the user's public key (must match CertChain).
- `nullifier: bytes32`: Derived from the card's RSA signature.
- `app_id_packed`: Platform identifier (`app_id`) packed as a single field element. The specific `app_id` value is platform-defined; each platform MUST use a unique value (see [Nullifier](#4-nullifier)).
- `challenge: bytes32`: Per-session challenge from the verifier.

#### DeviceSig Operations

The DeviceSig circuit MUST enforce:

1. **Credential signature verification**

   Verify the card's RSA signature over the TBS data:

   ```
   isValid := RSA_Verify(user_pk, TBS, σ_device)
   assert(isValid == 1)
   ```

2. **pk_commit computation**

   ```
   pk_commit := ChunkedPoseidonP256(user_pk_limbs || pk_blind)
   ```

   This MUST produce the same value as the CertChain circuit.

3. **Nullifier derivation**

   ```
   nullifier := Poseidon(σ_device)
   ```

4. **app_id binding**

   The `app_id` is extracted from the TBS data and packed as a single field element. The verifier MUST compare against the expected `app_id`.

5. **Challenge binding**

   The proof MUST bind to `challenge` as a public input. The circuit enforces binding via a Semaphore-style dummy square (`challengeSquared := challenge * challenge`).

### Outputs

- `nullifier: bytes32` (from DeviceSig)
- `pk_commit` (from both circuits, must be equal)

## Proof Output Format

Implementations MUST serialize proof outputs in a deterministic format. A complete verification submission consists of two linked proofs.

A minimal proof submission object SHOULD include:

```text
{
  cert_chain: {
    proof: bytes,
    public_inputs: {
      pk_commit: field_element,
      modulus: list<field_element>,
      smt_root: bytes32
    }
  },
  device_sig: {
    proof: bytes,
    public_inputs: {
      pk_commit: field_element,
      nullifier: bytes32,
      app_id_packed: field_element,
      challenge: bytes32
    }
  }
}
```

## Verifier API

This section specifies the network interface that conforming verifiers SHOULD expose so that wallets, SDKs, and relying parties can integrate against a stable contract independent of any specific verifier implementation.

The Verifier API does not modify the cryptographic protocol or circuit relations defined in [Specification](#specification). It defines the wire-level operations needed to deliver challenges to provers, accept proof submissions, expose deployment state, and report errors.

This section describes the 2-party deployment topology (relying party ↔ verifier). Other deployment topologies (e.g., 3-party flows where a wallet mediates between a merchant and the verifier, as in 3/ZK-AGE-VERIFICATION) are out of scope for this version. Where applicable, the term `challenge` used here corresponds to the verifier-issued nonce used elsewhere in OpenAC-based flows.

### Operations

Conforming verifiers MUST support the semantic operations listed below. RECOMMENDED URL paths are provided for HTTP/JSON deployments; gRPC and other transports MAY use equivalent method names.

#### Challenge Issuance

The verifier MUST expose a challenge issuance operation.

- RECOMMENDED HTTP endpoint: `POST /challenge`
- Request body: MAY be empty, or MAY include relying-party context fields (e.g., `app_id`) when a verifier serves multiple applications.
- Response body MUST include:
  - `challenge`: a 256-bit value, encoded consistently across the deployment (e.g., decimal field element, base64, or hex)
  - `app_id`: the verifier's configured platform identifier for this verification context, returned so the prover can confirm the value used to construct the proof matches what the verifier expects
  - `expires_at`: timestamp after which the challenge MUST be rejected
- Issued challenges MUST satisfy the freshness requirements in [Challenge (Anti-replay)](#3-challenge-anti-replay).

#### Proof Submission

The verifier MUST expose a linked proof submission operation that accepts the proof envelope defined in [Proof Output Format](#proof-output-format).

- RECOMMENDED HTTP endpoint: `POST /link-verify`
- Request body: the proof submission object specified in [Proof Output Format](#proof-output-format).
- Response body MUST include:
  - `decision`: one of `"pass"` or `"fail"`
  - `error_code`: present when `decision == "fail"`; one of the canonical values listed under [Error Codes](#error-codes)
  - `error_message`: human-readable supplementary message; SHOULD NOT contain raw proof bytes or other sensitive material
- Response body MAY include:
  - `verified_at`: timestamp at which verification was performed
  - additional non-PII metadata required for relying-party operation
- The verifier MUST perform every validation step required by [Proof Verification](#proof-verification) before returning `pass`.
- The verifier MUST persist the submitted `nullifier` per the rules in [Nullifier Persistence](#nullifier-persistence) before returning `pass`.

#### Status Queries

Verifiers SHOULD expose read-only status endpoints so that provers can detect stale local state before submitting proofs:

- Revocation root status: RECOMMENDED `GET /smt-root/status`. Response MUST include the current `smt_root` and SHOULD include an updated-at timestamp.
- Issuer certificate status: RECOMMENDED `GET /issuer-cert/status`. Response MUST include an enumeration of the issuer CA modulus values currently accepted by this verifier (matching the verifier's CA allowlist per [Certificate Model](#1-certificate-model)).

### Error Codes

When `decision == "fail"`, verifiers MUST set `error_code` to one of the following canonical values:

| Code | Meaning |
| --- | --- |
| `INVALID_PROOF` | One or both proofs failed cryptographic verification. |
| `INVALID_CHALLENGE` | The submitted `challenge` does not match a challenge issued by this verifier. |
| `EXPIRED_CHALLENGE` | The submitted `challenge` was issued by this verifier but has expired. |
| `STALE_REVOCATION_ROOT` | The submitted `smt_root` does not match the verifier's current revocation root. |
| `INVALID_APP_ID` | The submitted `app_id_packed` does not match this verifier's configured `app_id`. |
| `PK_COMMIT_MISMATCH` | The `pk_commit` from the CertChain proof does not equal the `pk_commit` from the DeviceSig proof. |
| `DUPLICATE_NULLIFIER` | The submitted `nullifier` has already been recorded for this `app_id`. |
| `MALFORMED_REQUEST` | The submission body could not be parsed against the expected schema. |
| `INTERNAL_ERROR` | The verifier encountered an internal failure unrelated to proof contents. |

Additional implementation-defined error codes MAY be returned but MUST NOT collide with the canonical names above.

### Nullifier Persistence

To enforce the duplicate-verification rejection required by [Proof Verification](#proof-verification), verifiers MUST implement a nullifier store satisfying:

- **Atomic insert-if-absent**: a successful proof submission MUST atomically record `(app_id, nullifier)` such that concurrent submissions of the same `(app_id, nullifier)` pair cannot both return `pass`.
- **Query**: the verifier MUST be able to determine whether a given `(app_id, nullifier)` pair has been previously recorded.
- **Durability**: recorded nullifiers MUST survive verifier process restarts and host failures appropriate to the deployment's availability requirements.
- **Retention**: recorded nullifiers MUST be retained for at least the lifetime of the issuer's certificate validity policy. Implementations MAY retain longer.

The choice of storage backend (SQL, key-value store, distributed log, etc.) is implementation-defined.

### Authentication

This version does not specify a verifier-to-relying-party authentication mechanism. Deployments MUST document the authentication model they rely on (e.g., mutual TLS, bearer tokens, IP allowlist, none). A future revision MAY standardize this.

### Transport

- HTTP/JSON over TLS is RECOMMENDED for general integration. Request and response bodies MUST be valid UTF-8 JSON conforming to the schemas defined above.
- gRPC over TLS is OPTIONAL and provides equivalent semantic operations. When gRPC is offered, method names SHOULD parallel the HTTP endpoint names (e.g., `Challenge`, `LinkVerify`, `SmtRootStatus`, `IssuerCertStatus`).
- Other transports (e.g., WebSocket, message queue) MAY be implemented provided the semantic operations and error contract above are preserved.

## Proof Verification

### Verifier MUST

- Validate both the CertChain proof and the DeviceSig proof against their respective public inputs.
- Assert that `pk_commit` from the CertChain proof equals `pk_commit` from the DeviceSig proof (constant-time comparison).
- Validate that `challenge` matches the session challenge issued by the verifier.
- Validate that `app_id_packed` matches the expected platform identifier.
- Validate challenge freshness (not expired).
- Validate that `smt_root` matches the latest known revocation tree root (from the CA's CRL or a trusted updater).
- Check whether the nullifier has already been used and reject duplicates.
- Persist nullifier state durably (i.e., nullifier rejection MUST survive verifier restarts). See [Nullifier Persistence](#nullifier-persistence) for the atomicity, query, durability, and retention rules.

### Verifier MAY

- Maintain a history of recently-valid challenges for resilience (implementation-defined), provided replay protection remains intact.

## Error Handling

Implementations MUST handle:

- Invalid proof
- Invalid or expired challenge
- Stale or unrecognized `revocation_root`

Implementations SHOULD handle:

- Duplicate nullifier

Error responses MUST include:

- Error code (set per the canonical taxonomy in [Error Codes](#error-codes))
- Error message
- Error details (when available)

## Interoperability Constraints

- Implementations MUST use the same `Encode()` canonicalization rules (base64, standard alphabet, with padding) to ensure nullifier consistency across verifiers.
- Implementations MUST use the same Poseidon hash configuration (circomlib, BN254 scalar field) for nullifier derivation.
- Implementations MUST use the same RSA verification parameters (RSA-2048, PKCS#1 v1.5, SHA-256) for certificate chain validation.
- Implementations MUST use the same SMT depth and hash configuration for revocation non-inclusion proofs.

## Certificate Renewal

The nullifier is derived from the card's RSA signature over `app_id`. If certificate renewal issues a new RSA key pair, the nullifier will change (different signing key produces a different signature). Therefore a user MAY be able to verify again after renewal if the renewal generates a new key pair.

If the renewal retains the same key pair, the nullifier remains stable.

## On-Chain Verification Status

On-chain verification was a design goal for this protocol (trustless nullifier registry, public verifiability). Extensive research and implementation work was conducted to evaluate feasibility. This section documents the findings and the rationale for deferring on-chain verification in this version.

OpenAC has three core properties that MUST NOT be compromised:

1. **Rerandomizable proofs** — required for unlinkability across presentations.
2. **Transparent setup** — no trusted setup ceremony required.
3. **Zero knowledge** — no credential attributes disclosed.

The circuit size is ~2^20 constraints. The current design uses Spartan2 with Hyrax PCS over the T256 (secp256r1) curve. No EVM chain provides native T256 ecAdd/ecMul precompiles; RIP-7212 / EIP-7951 exposes only `ECDSA.verify(hash, r, s, x, y)`, which cannot be used for the arbitrary curve arithmetic that Hyrax and IPA require.

### Approaches Evaluated

**1. Native Rust Verifier.** A self-contained Spartan2 verifier was built in Rust, independent of any external proving infrastructure. This serves as the foundation for off-chain verification and was used to validate subsequent on-chain approaches.

**2. SP1 Wrapper.** The native verifier was wrapped inside SP1 to generate a succinct proof of verification. This direction was abandoned due to: (a) no T256 precompiles available in SP1, (b) prohibitive credit cost (~44 credits per proof), and (c) no provers accepting jobs at the required resource limits. Cost scales proportionally with complexity, making this economically unviable.

**3. L2 Landscape Investigation.** All major L2s were surveyed for P-256 curve arithmetic support:

| Chain | RIP-7212 (Sig Verify) | P-256 ecAdd/ecMul | Useful for Spartan2? |
| --- | --- | --- | --- |
| Arbitrum | Yes | No | Yes, via Stylus |
| Optimism/Base | Yes | No | No |
| zkSync Era | Yes | No | No |
| Polygon PoS | Yes | No | No |
| Scroll/Linea | Partial | No | No |

No L2 currently provides the general-purpose P-256 curve arithmetic required. The only viable path is Arbitrum Stylus, which runs a WASM VM alongside the EVM with ~10–100x cheaper compute for cryptographic operations.

**4. Groth16 with the same R1CS circuits.** Reuse existing circuits, add a per-circuit trusted setup. Cheapest on-chain cost (~$0.003), but breaks transparent setup.

**5. Spartan2 + SPARK (native Solidity verifier).** SPARK preprocessing eliminates matrix storage but barely reduces per-verification gas (~3.7% savings). Estimated cost: ~200M gas on Arbitrum (~$20) for 2^20 constraints. Prohibitively expensive because every T256 curve operation runs as Solidity bytecode.

**6. Spartan2 + SPARK + WHIR.** Replace Hyrax PCS with WHIR (hash-based PCS). Cheaper verification (~$0.03–$0.93 batched), but WHIR is not additively homomorphic — breaks rerandomizable proofs.

**7. Spartan2 → Groth16 wrapper.** Verify the Spartan proof inside a Groth16 circuit. Cheap on-chain verification, but reintroduces trusted setup and adds 30–120s prover overhead.

**8. Spartan2 + KZG.** Replace Hyrax with KZG (e.g., HyperKZG). Cheap on-chain verification (~$0.01–$0.05), preserves rerandomization and ZK, but requires trusted setup / universal SRS.

**9. Arbitrum Stylus Verifier (Rust → WASM).** A fully self-contained Spartan2 verifier was built targeting Stylus with custom T256 field and curve arithmetic, no external crypto dependencies, compiled to WASM, and deployed on Arbitrum Sepolia ([0xfcd5fc2da39f4dc822835f99b5a70d12e32b24fd](https://sepolia.arbiscan.io/address/0xfcd5fc2da39f4dc822835f99b5a70d12e32b24fd#code)). This preserves all three core properties. However, it is currently blocked: Stylus caps contracts at 24 KB brotli-compressed (current build is ~349 KB uncompressed), and RPC clients reject the ~100 KB calldata required for proof submission.

### Summary

| Option | Transparent Setup | Rerandomizable | ZK | On-Chain Cost | Status |
| --- | --- | --- | --- | --- | --- |
| Groth16 | No | Yes | Yes | ~$0.003 | Breaks transparent setup |
| Spartan2 + SPARK (Solidity) | Yes | Yes | Yes | ~$20 | Prohibitively expensive |
| Spartan2 + SPARK + WHIR | Yes | No | Yes | ~$0.03–$0.93 | Breaks rerandomization |
| Spartan2 → Groth16 wrapper | No | Yes | Yes | ~$0.003 | Breaks transparent setup |
| Spartan2 + KZG | No | Yes | Yes | ~$0.01–$0.05 | Breaks transparent setup |
| SP1 wrapper | Yes | Yes | Yes | N/A | Economically unviable |
| Arbitrum Stylus | Yes | Yes | Yes | TBD | Blocked (contract size + calldata) |

Only two options preserve all three core properties: Spartan2 + SPARK as a Solidity contract (prohibitively expensive) and Arbitrum Stylus (blocked on contract size and calldata limits). Every other option compromises at least one core property.

### Conclusion

On-chain verification is deferred for this version. Off-chain verification via Spartan2 with Hyrax PCS is the only conformance mode. A future version MAY revisit on-chain verification if the Stylus size blocker is resolved or if L2s add native P-256 curve arithmetic precompiles.

For the full research details, see [Exploring Spartan2 Proofs for On-Chain Verification](https://github.com/zkmopro/zkID/blob/main/wallet-unit-poc/onchain-research.md).

# Security Considerations

## Privacy and Security Assumptions

The protocol assumes:

- The security of Spartan2 with Hyrax polynomial commitment scheme (transparent setup — no trusted setup required).
- The unforgeability of the RSA signature scheme (RSA-2048 and RSA-4096, PKCS#1 v1.5) used for certificate signing and credential signatures.
- Collision resistance of SHA-256 (for TBS hashing) and Poseidon over secq256r1 (for nullifier derivation, pk_commit computation, and revocation leaf computation).
- Correct and unique domain separation via `app_id`.
- Correct canonical encoding via `Encode()` (base64, standard alphabet, with padding).
- Freshness of the revocation SMT snapshot (i.e., the snapshot reflects the latest CRL published by the CA). The CertChain circuit verifies the SMT non-inclusion proof against the `smtRoot` public input, so the verifier checks the root matches the latest published value. Freshness depends on the snapshot distribution frequency.
- The nullifier is derived from the card's RSA signature, which requires possession of the card's private key. An adversary cannot compute nullifiers without possession of the card's private key.
- Per-session `pk_blind` provides cross-session unlinkability. The blinding value MUST be fresh 248-bit randomness for each session. Reusing `pk_blind` across sessions would allow the verifier to link presentations.
- A future version SHOULD add a domain-separation tag to the nullifier's signed message to prevent cross-protocol correlation when the same card key is used by multiple ZK protocols.

## Privacy and Security Best Practices

- Proof generation SHOULD be performed on the user's device to reduce risk of certificate exposure.
- Revocation witness generation MUST be performed locally on the user's device (see [Witness Retrieval](#witness-retrieval)).
- Verifiers SHOULD minimize logging of public inputs, particularly nullifier, to reduce metadata retention.

## Linkability

The nullifier is only visible to the forum platform verifier. Domain separation via `app_id` is REQUIRED to prevent cross-platform nullifier correlation.

## Revocation Witness Privacy

Client-side witness generation (see [Witness Retrieval](#witness-retrieval)) ensures that the prover's `sn` never leaves the device. This eliminates the metadata leakage risk present in server-side witness retrieval models, where the server would learn which `sn` is being checked.

The prover downloads the full SMT snapshot, which is a public dataset derived from the CA's CRL. Downloading the snapshot does not reveal which certificate the prover holds.

## Revocation Freshness

There is an inherent delay between a CA revoking a certificate (publishing a new CRL), the SMT snapshot being rebuilt, and the prover downloading the updated snapshot. During this window, a revoked certificate can still produce valid proofs.

- Verifiers SHOULD define a maximum acceptable `revocation_root` age.
- Snapshot publishers SHOULD include the CRL publication timestamp alongside the `revocation_root`.
- Provers SHOULD download the latest available snapshot before each verification attempt.

## Known Limitations

**Renewal limitation (v0.1)**
If certificate renewal issues a new RSA key pair, a user MAY verify again (the nullifier changes because the signing key changed).

**Certificate sharing (v0.1)**
This version does not include device binding. Certificate sharing across devices is not cryptographically prevented.

**Revocation latency (v0.1)**
The revocation SMT snapshot update is not real-time. The window between CRL publication and snapshot rebuild depends on the update mechanism (manual, automated). During this window, revoked certificates remain usable.

**Dual-credential nullifier divergence (v0.1)**
Holders of both a physical card and a digital credential have different RSA key pairs per credential. Since the nullifier is derived from the card's RSA signature, each credential produces a different nullifier, allowing one verification per credential type. This is a known, accepted trade-off.

**On-chain verification (v0.1)**
On-chain verification is deferred for this version. See [On-Chain Verification Status](#on-chain-verification-status) for the full rationale.

**Server-held signing keys (v0.1)**
Some deployments (e.g., the TW FidO mobile app) hold the user's RSA signing key on a sign server rather than on a tamper-resistant card under the user's sole control. In such deployments, the security guarantee "an adversary cannot compute nullifiers without possession of the card's private key" is weakened to "an adversary cannot compute nullifiers without access to the sign server's signing pathway." Deployments using server-held keys MUST document this trust assumption. See [Deployment Profiles](#deployment-profiles) for the per-deployment characteristics.

# Implementation Notes

A reference implementation is available at [zkID](https://github.com/zkmopro/zkID). Implementation tasks and progress are tracked at [ZK-based-Human-Verification](https://github.com/zkmopro/ZK-based-Human-Verification/issues).

The current implementation includes:

- **Mobile native bindings** (iOS / Android) via [mopro-ffi](https://github.com/zkmopro/mopro), enabling client-side proof generation on mobile devices.
- **Mobile proof generation flow** integrated with the [Ptt-iOS](https://github.com/Ptt-official-app/Ptt-iOS) and [Ptt-Android](https://github.com/Ptt-official-app/Ptt-Android) forum apps.
- **WASM browser proof generation** via mopro, enabling client-side proof generation in web apps.
- **Server backend verification** with OpenAC verification logic ported from Rust to GO via FFI for the BBS server backend.
- **Client-side SMT revocation** with local snapshot download and local non-inclusion proof generation (see [Witness Retrieval](#witness-retrieval)).

Implementations SHOULD provide test vectors for:

- `Encode()` canonicalization,
- nullifier derivation,
- signature verification inputs,
- SMT non-inclusion proof generation and verification.

## Deployment Profiles

The protocol has been deployed against two distinct credential profiles in the MOICA / TW ecosystem. They share the same cryptographic primitives (RSA-2048/4096 chains, Poseidon, Spartan2/Hyrax) but differ in how the user's signing key is held and accessed.

- **Physical IC card (Citizen Digital Certificate).** The user's RSA-2048 private key is held on a tamper-resistant smartcard issued by MOICA. Signing operations require the card to be physically present and unlocked with a PIN. Proof generation runs on the user's device (mobile app or desktop with a card reader). This profile satisfies the spec's "card private key required" guarantee directly.

- **TW FidO (mobile app).** The user's RSA private key is provisioned to and held on a remote sign server operated by the issuer. The mobile app authenticates the user (typically with FIDO2 biometric / device key) to the sign server, which then performs the RSA signing operation server-side. Compared to the physical IC card profile, the trust boundary is moved from "user's tamper-resistant hardware" to "issuer's sign server." See the §Known Limitations entry on Server-held signing keys.

Other deployments MUST document their key-storage model and the resulting threat-model assumptions.

## Verifier Implementations

Reference verifier implementations are available across multiple deployment surfaces. Several currently live in the [`zkmopro/zkID`](https://github.com/zkmopro/zkID) fork of this repository, where ongoing implementation work happens; this spec's canonical home is `privacy-ethereum/zkID`.

- **Production HTTP / gRPC server**: [zkmopro/go-zkid-verifier](https://github.com/zkmopro/go-zkid-verifier) — Go-native verifier with a CGO FFI bridge to a Rust cryptographic backend. Exposes endpoints for challenge issuance (`POST /challenge`), linked proof verification (`POST /link-verify`), revocation root status (`GET /smt-root/status`), and issuer certificate cache state (`GET /issuer-cert/status`), with gRPC equivalents on a parallel port.
- **Portable WASM verifier**: [zkmopro/zkID/wallet-unit-poc/spartan2-wasm](https://github.com/zkmopro/zkID/tree/main/wallet-unit-poc/spartan2-wasm) — Rust-to-WASM verifier suitable for browser and mobile contexts. Exposes `verify(proof_bytes, vk_bytes)` and `link_verify(cert_pubs, device_pubs)` for cross-proof `pk_commit` matching.
- **Verifier SDK for relying parties**: [zkmopro/zkID/wallet-unit-poc/openac-sdk](https://github.com/zkmopro/zkID/tree/main/wallet-unit-poc/openac-sdk) — TypeScript SDK that validates proofs and extracts public values for relying-party integration.
- **Browser verifier reference**: [zkmopro/zkID/wallet-unit-poc/web](https://github.com/zkmopro/zkID/tree/main/wallet-unit-poc/web) — Vite-based browser frontend demonstrating end-to-end verification.
- **Arbitrum Stylus on-chain verifier (proof of concept)**: deployed on Arbitrum Sepolia at [`0xfcd5fc2da39f4dc822835f99b5a70d12e32b24fd`](https://sepolia.arbiscan.io/address/0xfcd5fc2da39f4dc822835f99b5a70d12e32b24fd#code). See [On-Chain Verification Status](#on-chain-verification-status) for current status and known blockers.

## User Experience Guidelines

The verification flow involves sensitive credential operations. Implementations SHOULD follow these guidelines to ensure users can make informed decisions about their data.

### Privacy Communication

The UI MUST clearly communicate the following at each stage of the flow:

1. **What the user is verifying.** The user is using a government-issued certificate to verify eligibility for a forum badge. The specific eligibility condition (e.g., possession of a valid certificate from a trusted issuer) SHOULD be stated in plain language.
2. **What stays on the device.** The full certificate data, PIN, and private key material never leave the device. Revocation status is checked locally. The UI MUST state this explicitly before and during proof generation.
3. **What is sent to the verifier.** Only the public inputs required for verification (nullifier, challenge, revocation root, CA public key commitment, and the proof) are submitted. The UI SHOULD list these in user-facing terms (e.g., "information needed to confirm your eligibility") with raw field names available under a collapsed technical details section.
4. **What is not sent.** Full certificate data, PIN, and raw personal identity details are not transmitted. The UI MUST state this on the consent / confirmation screen before submission.

### Consent Before Submission

Implementations MUST include an explicit consent step after proof generation and before submission to the verifier. This step MUST:

- confirm that verification data has been prepared locally and has not yet been sent,
- summarize what will and will not be sent,
- require an explicit user action (e.g., button tap) to proceed with submission.

### Technical Detail Separation

Raw cryptographic values, proof-system internals, backend identifiers, and protocol-level field names (e.g., circuit names, proving key names, witness states, raw public input values) SHOULD NOT appear in the main UI by default.

These values SHOULD be preserved in a collapsed "technical details" section for debugging and support purposes. Users SHOULD be able to copy diagnostic information from this section when reporting errors.

### Error Handling UX

Error states MUST:

- display a user-readable title and plain-language explanation,
- recommend a specific next action (retry, restart, or contact support),
- include an error code for support reference,
- NOT expose PIN, full certificate data, or raw private key material in error output.

Diagnostic information sufficient for engineering debugging (e.g., error code, failing step, timestamp, browser/OS, verifier response status) SHOULD be available under a collapsed section or via a "copy diagnostic info" action.

### PIN Safety

When the verification flow requires PIN entry (e.g., for smartcard-based certificate access):

- the UI MUST warn users about the lockout threshold before PIN entry,
- the UI MUST display remaining PIN attempts after each incorrect entry, and
- the UI MUST clearly distinguish between a session-level PIN unlock and a permanent card lockout.

# References

- [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt)
- [FIPS 180-4 (SHA-256)](https://csrc.nist.gov/publications/detail/fips/180/4/final)
- [Poseidon Hash (circomlib)](https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom)
- [OpenAC (paper)](https://github.com/privacy-ethereum/zkID/blob/main/paper/zkID.pdf)
- [ZK Circuit Specification for Human Verification (prior art)](https://github.com/zkmopro/ZK-based-Human-Verification/issues/3)
- [Revocation in zkID: Merkle Tree Based Approaches (PSE)](https://pse.dev/blog/revocation-in-zkid-merkle-tree-based-approaches)
- [MOICA Certificate Revocation List](https://moica.nat.gov.tw/del.html)
- [Client-side SMT proof generation for revocation privacy](https://github.com/zkmopro/ZK-based-Human-Verification/issues/16)
- [Exploring Spartan2 Proofs for On-Chain Verification](https://github.com/zkmopro/zkID/blob/main/wallet-unit-poc/onchain-research.md)

# Glossary

## Certificate

A CA-signed X.509 certificate `S` containing a serial number (`sn`), attributes `m`, and an RSA signature `σ`.

## Nullifier

A deterministic value derived in zero-knowledge and used to prevent duplicate verification.

## Challenge

A verifier-provided nonce bound to the proof to prevent replay.

## Revocation List

A set of certificate identifiers that have been invalidated by the issuing CA, represented as a Sparse Merkle Tree for ZK-compatible non-inclusion proofs.

## Serial Number (`sn`)

The X.509 serial number field of a certificate, used as the key for revocation lookups. The `sn` does not directly reveal the prover's identity and is used locally to generate a non-inclusion witness from a downloaded SMT snapshot.

## Sparse Merkle Tree (SMT)

A binary Merkle trie where each element has a fixed position determined by its key. Supports efficient non-membership proofs by demonstrating that a given position is empty.

# Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).

# zkID Circuit Specification

This document describes the Circom circuits in this directory.

## Overview

The circuits verify Taiwan Citizen Digital Certificate (MOICA) X.509
certificates signed with RSA-SHA256, plus a per-session user signature
over arbitrary data (the "TBS" sent to the HiPKI card). They also assert
non-revocation against a Sparse Merkle Tree (SMT).

## Active circuits

| Circuit              | Template           | Description                                                              |
| -------------------- | ------------------ | ------------------------------------------------------------------------ |
| `certChainRS2048`  | `CertChainRSA256`  | Circuit A — cert chain + revocation + pkCommit (MOICA-G2)               |
| `certChainRS4096`  | `CertChainRSA256`  | Circuit A — cert chain + revocation + pkCommit (MOICA-G3)               |
| `userSigRS2048`  | `UserSigRSA256`  | Circuit B — user signature + nullifier + appIdPacked + pkCommit         |

The two-circuit split replaces the former monolithic `FullCertRSA256VerifyWithRevocation`.
Circuit A and Circuit B are linked via `pkCommit`: the verifier checks
`pkCommit_A == pkCommit_B` to bind both proofs to the same user key.

## What the circuits prove

### Circuit A — CertChain (`CertChainRSA256`)

1. **Cert chain verify** — `issuerRsaModulus` (MOICA) verifies
   `issuerRsaSignature` over `issuerTbs` (the TBS portion of the user's
   cert). Proves that MOICA certified the user's public key.
2. **DER parsing** — the circuit walks the TBS from its first byte:
   `VerifySerialNumber` reads the serial at its fixed offset, `VerifyValidity`
   continues to the `Validity` field, and `LocateModulus` continues past the
   subject Name to the `SubjectPublicKeyInfo`. Every offset is derived from
   the DER structure; the prover supplies none. See §"Structural walk" below.
3. **Revocation** — `SMTNonMembershipVerifier` proves `serialNumber` is **not**
   in the revocation tree rooted at `smtRoot`.
4. **Validity period** — `VerifyValidity` asserts
   `notBefore <= currentTime <= notAfter`. See §"Validity period" below.
5. **Key usage** — `VerifyKeyUsage` asserts the certificate's keyUsage is
   exactly `digitalSignature`. See §"Key usage" below.
6. **Linking** — `pkCommit = ChunkedPoseidonP256(userRsaExtractedModulus ‖ pkBlind)`,
   where `pkBlind` is a per-session uniform 248-bit value sampled by the
   prover. The same value is used in Circuit B; the verifier checks
   `pkCommit_A == pkCommit_B`. See §"Why per-session randomness for `pkBlind`"
   below.

### Circuit B — UserSig (`UserSigRSA256`)

1. **App-id binding** — the public output `appIdPacked` is constrained to
   equal `tbs[0..31]` (the SHA-256-padded payload the card signs) packed
   little-endian into one field element. The verifier unpacks and byte-compares
   against the issued challenge's `app_id`.
2. **User signature verify** — `userPkLimbs` verifies `userRsaSignature`
   over `tbs`. Proves the holder of the user's private key signed the app-id bytes.
3. **Linking** — same `pkCommit` formula as Circuit A, using the same
   `pkBlind` value.
4. **Nullifier** — `nullifier = ChunkedPoseidonP256(userRsaSignature)`
   (public output). PKCS#1 v1.5 signing is deterministic and the signature
   never leaves the card, so the nullifier is deterministic per
   `(card, app_id)` and unforgeable without the card's private key.

## Public inputs / outputs

### Circuit A — CertChain

| Signal                  | Visibility    | Notes                                                  |
| ----------------------- | ------------- | ------------------------------------------------------ |
| `issuerRsaModulus[k]`   | public input  | MOICA's RSA public key (trust anchor)                  |
| `smtRoot`               | public input  | Revocation SMT root                                    |
| `currentTime`           | public input  | Verifier's time as the decimal integer `YYMMDDHHMMSS` (UTC) |
| `pkCommit`              | public output | Links to Circuit B                                     |

Public-value vector layout (in declaration order, outputs first):
- RS2048: `[pkCommit, issuerRsaModulus[17], smtRoot, currentTime]` — 20 elements
- RS4096: `[pkCommit, issuerRsaModulus[34], smtRoot, currentTime]` — 37 elements

### Circuit B — UserSig

| Signal         | Visibility    | Notes                                                              |
| -------------- | ------------- | ------------------------------------------------------------------ |
| `challenge`    | public input  | Verifier-issued per-session nonce; bound via dummy square          |
| `pkCommit`     | public output | Must match Circuit A's `pkCommit`                                  |
| `nullifier`    | public output | `ChunkedPoseidonP256(userRsaSignature)`; per-(card, app_id) ID    |
| `appIdPacked`  | public output | `tbs[0..31]` packed little-endian into one field element           |

Public-value vector layout: `[pkCommit, nullifier, appIdPacked, challenge]` — 4 elements.

All other signals (user cert bytes, RSA signatures, SMT proof path,
`tbs`, `pkBlind`) are private.

## Revocation

Revocation uses a Sparse Merkle Tree non-membership proof against the SMT
maintained by the
[`moica-revocation-smt`](https://github.com/privacy-ethereum/moica-revocation-smt)
service. Circuit A verifies that the cert's `serialNumber` is not present in
the tree rooted at `smtRoot`.

## Validity period

Revocation alone does not exclude expired certificates: MOICA's CPS keeps a
revoked certificate on the CRL only until it expires, and the revocation SMT
mirrors the current CRL. Circuit A therefore checks the validity period itself.

`currentTime` is a public input, the decimal integer `YYMMDDHHMMSS` in UTC —
the same 12 digits a DER `UTCTime` carries, so the two compare as integers.
The verifier MUST check `currentTime` against its own clock; the circuit only
proves `notBefore <= currentTime <= notAfter`.

### Verifier time window

The verifier accepts a proof only if, at the moment it verifies,

```
now - maxAge <= currentTime <= now + maxAhead
```

where `now` is the verifier's own clock. The two bounds do different jobs:

- `maxAge` is the security-relevant bound. A certificate that expired less
  than `maxAge` ago still passes, so `maxAge` SHOULD be no longer than the
  challenge lifetime plus the clock skew the verifier tolerates. Recommended:
  10 minutes.
- `maxAhead` can be generous. A `currentTime` in the future makes the expiry
  check stricter: the certificate must stay valid until then. The cost is on
  the other end: a certificate whose `notBefore` is still in the future can
  pass up to `maxAhead` early. Recommended: 24 hours.

`currentTime` is public, so an exact timestamp reveals the prover's clock to
anyone who sees the proof. A generous `maxAhead` lets the prover use a coarse
value instead, such as the last second of the current UTC day, which every
prover on that day shares.

## Structural walk

The offsets of `Validity` and of the user's RSA modulus are derived inside the
circuit, never supplied by the prover:

| Offset                         | Bytes                                   | Constraint                         |
| ------------------------------ | --------------------------------------- | ---------------------------------- |
| 0                              | `30 82 hh ll` outer SEQUENCE            | `30 82` pinned                     |
| 4                              | `a0 03 02 01 02` version v3             | pinned (v1 TBSes are rejected)     |
| 9                              | `02 LL` serial INTEGER                  | `1 <= LL <= 20`                    |
| `p1 = 11 + LL`                 | AlgorithmIdentifier, 15 bytes           | pinned to `sha256WithRSAEncryption` |
| `p1 + 15`                      | `30 NN` issuer Name                     | short-form length, `NN < 128`      |
| `p3 = p1 + 17 + NN`            | `30 1e 17 0d <12 digits> 5a 17 0d <12 digits> 5a` | tags pinned, digits range-checked |
| `p3 + 32`                      | `30 SS` or `30 81 SS` subject Name      | `SS < 128`, or `81` with `SS >= 128` |
| `q` = end of subject Name      | 28-byte head of an RSA-2048 `SubjectPublicKeyInfo` | pinned                  |
| `q + 28`                       | `02 82 01 01 00` modulus INTEGER        | pinned; 256 modulus bytes follow   |
| `e = q + 289`                  | `02 03 01 00 01` public exponent        | pinned (65537)                     |
| `e + 5`                        | `a3 82 hh ll 30 82 hh ll` Extensions    | tags pinned                        |
| `e + 13`                       | `30 1f 06 03 55 1d 23 04 18 30 16 80 14 <20>` authorityKeyIdentifier | header pinned |
| `e + 46`                       | `30 1d 06 03 55 1d 0e 04 16 04 14 <20>` subjectKeyIdentifier | header pinned |
| `e + 77`                       | `30 0e 06 03 55 1d 0f 01 01 ff 04 04 03 02 07 80` keyUsage | pinned in full |

`p3 + 35 <= 210`, `q + 28 <= 493` and `e + 93 <= 847`, so the walk reads only
the first 1024 bytes of `issuerTbs`. The modulus INTEGER and the 93 bytes read
from `e` are bounded by `actualIssuerTbsLength` through `AssertSliceInTBS`.

`actualIssuerTbsLength` is bound to the length the TBS declares in its own
outer header (`issuerTbs[2..4]` + 4), so those bounds refer to the signed TBS
and cannot reach into the SHA-256 padding.

Deriving the modulus offset closes audit v3 Finding 1: the circuit no longer
relies on the byte pattern `02 82 01 01 00` being unique within a MOICA TBS.

Limits, all of which fail closed:

- Only `UTCTime` is accepted. A certificate whose `notBefore` or `notAfter` is
  in 2050 or later uses `GeneralizedTime` and is rejected.
- Both years must be below 50. `UTCTime` years 50..99 mean 1950..1999, which
  the integer comparison would otherwise treat as later than any 20YY date.
- An issuer Name longer than 127 content bytes is rejected.
- A subject Name longer than 255 content bytes is rejected.
- A subject key that is not 2048-bit RSA is rejected.
- A TBS without the explicit v3 version block is rejected.
- See §"Key usage" for the limits on extensions.

## Key usage

MOICA issues each card two certificates over two different keys: a signing
certificate (keyUsage `digitalSignature`) and an encryption certificate
(`keyEncipherment`, `dataEncipherment`). Both are signed by the same CA and
are otherwise identical in structure, and the card performs a private-key
operation with either key. Without a keyUsage check, one card would yield two
`pkCommit` / `nullifier` chains per app.

Circuit A therefore requires the keyUsage extension to be exactly
`digitalSignature`, critical. MOICA end-entity certificates carry their
extensions in a fixed order — authorityKeyIdentifier (keyIdentifier only),
subjectKeyIdentifier, keyUsage, then policies, directory attributes, CRL and
AIA — so keyUsage sits at a structurally derived offset (see §"Structural
walk"). X.509 allows one keyUsage extension per certificate, so pinning the
third extension pins the certificate's key usage.

Certificates with a different extension order, without keyUsage, with an
Extensions block shorter than 256 bytes, or with a public exponent other than
65537 are rejected.

## Why per-session randomness for `pkBlind`

`pkCommit` must hide the user's RSA modulus from anyone who sees only the
public proof outputs (`pkCommit`, `nullifier`, `appIdPacked`,
`issuerRsaModulus`, `smtRoot`). The assumed adversary holds the full MOICA
cert directory — every citizen's `userPkLimbs`. Any deterministic derivation of
`pkBlind` from public or leaked inputs lets that adversary recompute
`pkCommit` for each `userPkLimbs` and match against the observed value.

A per-session uniform 248-bit `pkBlind` removes that attack: every `userPkLimbs`
candidate is equally consistent with the observed `pkCommit`.

`pkCommit` only needs to link Circuits A and B within a single submission,
so it doesn't need to be reproducible. Sybil resistance per `(card, app_id)`
is carried by `nullifier = ChunkedPoseidonP256(userRsaSignature)` instead,
whose secrecy rests on the RSA private key never leaving the card.

## See also

- [`../ecdsa-spartan2/README.md`](../ecdsa-spartan2/README.md) — Rust prover CLI
- `circuits/components/smtNonmembership.circom` — SMT non-membership verification
- `circuits/components/smtVerifierP256.circom` — SMT verifier with Poseidon-P256 hash
- `circuits/components/poseidonP256.circom` — Poseidon hash over secq256r1
- `circuits/components/pkCommit.circom` — `ChunkedPoseidonP256` for `pkCommit`
- `circuits/utils/utils.circom` — cert parsing helpers (`VerifySerialNumber`, `VerifyValidity`, `LocateModulus`, `VerifyKeyUsage`, `ExtractModulus`, `PackBytes`, `PoseidonBytes`)

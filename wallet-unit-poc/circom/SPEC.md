# ZK-ID Circuit Specification

## Overview

This document describes the circuits used for privacy-preserving identity verification using zero-knowledge proofs (ZKPs). These circuits enable verification of JWT claims without revealing sensitive personal data.

### List of Circuits

- `jwt` - Validates a JWT using ES256 and exposes decoded claims

- `claim-decoder` - Decodes Base64 encoded claims

- `utils` - Helper templates for selective disclosure

- `age-verifier` - Checks if a birth date claim represents a user over 18

- `es256` - ES256 (ECDSA) signature verification circuit

---

## JWT Circuit Parameters

| Parameter             | Description                                                |
| --------------------- | ---------------------------------------------------------- |
| `n, k`                | Parameters defining ES256 signature size and field chunks. |
| `maxMessageLength`    | Maximum length of JWT message (header + payload).          |
| `maxB64HeaderLength`  | Maximum Base64-encoded JWT header length.                  |
| `maxB64PayloadLength` | Maximum Base64-encoded JWT payload length.                 |
| `maxMatches`          | Maximum number of claims/substrings to check.              |
| `maxSubstringLength`  | Maximum length for substring matches.                      |
| `maxClaimsLength`     | Maximum length for individual claims.                      |

---

## JWT Circuit Inputs

| Input            | Description                                              |
| ---------------- | -------------------------------------------------------- |
| `message`        | JWT message containing header and payload                |
| `messageLength`  | Length of the JWT message                                |
| `periodIndex`    | Index of the period separating header and payload in JWT |
| `sig_r`, `sig_s` | Components of JWT ES256 signature                        |
| `pubkey`         | Public key used for JWT signature verification           |
| `matchesCount`   | Number of substring matches provided                     |
| `matchSubstring` | Array of substrings (hashed claims)                      |
| `matchLength`    | Length of each substring                                 |
| `matchIndex`     | Starting index of each substring within the payload      |
| `claims`         | Array of raw Base64-encoded claims                       |
| `claimLengths`   | Length of each claim                                     |
| `decodeFlags`    | Flags indicating which claims should be decoded (0/1)     |

---

## JWT Circuit Outputs

| Output       | Description                                                  |
| ------------ | ------------------------------------------------------------ |
| `jwtClaims` | Array of decoded claims returned by `ClaimDecoder` |

---

## Constraints

1.  **ES256 Signature Verification**

    - Validate the ECDSA signature (ES256) of the JWT header and payload using the provided public key.

    - Hash the JWT payload using SHA-256.

2.  **ClaimDecoder**

    - Decode JWT claims from Base64 format only when the corresponding `decodeFlags[i]` is `1`.

    - Claims with `decodeFlags[i]` set to `0` are replaced with a padded Base64 string of `'A'` characters so that decoding always succeeds.

    - Hash decoded raw claims using SHA-256.

3.  **ClaimComparator**

    - Compute hashes of decoded raw claims.

    - Decode existing hashed claims from selective disclosure inputs.

    - Ensure claims with non-zero length (`claimLengths[i] > 0`) match the provided hashed claims.

4.  **HeaderPayloadExtractor**

    - Decode JWT header from Base64.

    - Decode JWT payload from Base64.

5.  **SubString Inclusion Check**

    - Verify if hashed claims (`matchSubstring`) match values in `_sd[]` in the decoded JWT payload.

---

## Workflow

1.  **JWT Signature Verification:** Validate JWT signature and hash payload.

2.  **Claims Decoding:** Decode claims from JWT payload and hash them.

3.  **Claims Matching:** Compare decoded and hashed claims against selective disclosure data.

## Claim Value Normalization and Hashing

**HashModScalarField**

- The 256 digest bits build the low and high 128-bit limbs directly, then one subtraction of the scalar order reduces them. A digest at or above the base-field modulus reduces correctly. Shared with the mdoc circuit.

## AgeVerifier Circuit

This circuit operates separately from `JWT`. It checks whether a birth date claim corresponds to a user who is 18 years or older.

### Inputs

| Input | Description |
| --- | --- |
| `claim` | Decoded claim bytes containing a YYMMDD birth date |
| `currentYear` | Current year |
| `currentMonth` | Current month |
| `currentDay` | Current day |

### Output

| Output | Description |
| --- | --- |
| `ageAbove18` | `1` if the extracted age is at least 18, otherwise `0` |

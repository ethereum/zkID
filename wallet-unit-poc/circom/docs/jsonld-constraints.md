# JSONLD circuit: constraint breakdown

Measured with `circom --r1cs --O2 --prime secq256r1` on each template alone, at the
production instantiation `JSONLD(2240, 2, 128, 31, 64, 252)`. Counts are non-linear
constraints (all constraints in these circuits are non-linear after O2).
`yarn compile:jsonld` reports 1,830,784 for the whole circuit. The circomkit tester
builds at O1 and reports 2,102,097, so use the O2 figure for sizing.

## Per component

| Component | Instances | Each | Total | Share |
|---|---|---|---|---|
| SHA-256 of the padded document, `Sha256Bytes(2240)` (35 blocks) | 1 | 1,105,943 | 1,105,943 | 60.4% |
| Signing-input SHA-256, `Sha256Bytes(192)` (3 blocks) plus mod-q reduction | 1 | 97,195 | 97,195 | 5.3% |
| ECDSA-P256 verify, `ECDSA()` | 1 | 14,094 | 14,094 | 0.8% |
| `AssertZeroPadding(2240)` on the document | 1 | 31,360 | 31,360 | 1.7% |
| Poseidon hash of the document, `HashBytesToFieldWithLen(2240)` | 1 | 23,376 | 23,376 | 1.3% |
| `NQuadsSubject` (3 substring checks plus subject charset) | 1 | 52,173 | 52,173 | 2.9% |
| `NQuadsClaimLine` for a claim (7 substring checks, line start, charsets) | 2 | 124,050 | 248,100 | 13.6% |
| `NQuadsClaimLine` for the deviceKey line (value up to 252) | 1 | 126,081 | 126,081 | 6.9% |
| `JsonLdDeviceKey(252)` (base64url decode, JWK anchors, x/y extract) | 1 | 60,882 | 60,882 | 3.3% |
| `JsonLdValueNormalizer(64)` (incl. one SHA block for digest64) | 2 | 32,650 | 65,300 | 3.6% |
| Everything else (flag checks, name hashes, two length-byte selects, wiring) | | | about 6,300 | 0.3% |
| **Sum of parts** | | | 1,824,504 + rest | |
| **Whole circuit** | | | **1,830,784** | |

ES256 as a whole is 111,289: the ECDSA verify is only 14,094, and the other 97,195 is
the SHA-256 of the 121-byte signing input (3 blocks, 94,483) plus the reduction mod the
scalar field order. The figure of about 3k per `Secp256r1Mul` is consistent with that.

### Inside the pieces

- `Sha256Bytes(64)` (one block) is 30,497. The document hash costs about 31.6k per
  block. The digest64 SHA in each value normalizer is one block of this kind and is
  about 30.5k of that component's 32,650 (the base `ClaimValueNormalizer(64)` is 2,003).
- `CheckSubstrInclusionPoly(2240, m)` costs 16,314 + about 10.4 per piece byte, with the
  string term dominant: it is about 7.3 constraints per document byte.

  | Piece length m | Cost |
  |---|---|
  | 1 | 16,314 |
  | 3 | 16,334 |
  | 4 | 16,344 |
  | 9 | 16,394 |
  | 27 | 16,574 |
  | 31 | 16,614 |
  | 58 | 16,905 |
  | 64 | 17,001 |
  | 128 | 17,698 |
  | 252 | 19,043 |

  The same check over the 189-byte decoded JWK with a 5-byte anchor is 1,997.
- Substring checks per instance:
  - Claim line: 7 checks (`<`, subject, `> <BASE`, name, `> "`, value, `" .\n`), 116,879 in total, of 124,050.
  - DeviceKey line: 7 checks, 118,701 in total, of 126,081.
  - Subject line: 3 checks, 50,947 in total, of 52,173.
  - All 24 checks over the document: 403,406 (22% of the circuit).
  - The remainder of each line component is `AssertLineStart(2240)` (4,507) plus the
    name and value charset checks (about 2.5k to 3k).
- `JsonLdDeviceKey(252)` 60,882: two JWK anchor checks (3,994), the 189-byte Poseidon hash
  (2,103), and about 55k for the base64url alphabet check over 252 characters, the
  decode, the masking, and the two 44-byte windows with canonical-range checks.
- `HashBytesToFieldWithLen(31)` (the claim-name identity hash) is 519.

## As a function of maxDocLen

`JSONLD(maxDocLen, 2, 128, 31, 64, 252)`, measured:

| maxDocLen | Constraints | Delta vs previous |
|---|---|---|
| 1,280 | 1,161,141 | |
| 1,792 | 1,517,053 | +355,912 for 512 bytes |
| 2,240 | 1,830,784 | +313,731 for 448 bytes |
| 2,688 | 2,142,673 | +311,889 for 448 bytes |
| 3,200 | 2,499,100 | +356,427 for 512 bytes |

It is linear: about **44,600 constraints per extra 64-byte block** (about 697 per byte),
with a fixed part of about **270k** that does not depend on the document size:

    constraints(maxDocLen) ~= 269,500 + 697 * maxDocLen

Per +64 bytes (one SHA block), roughly: SHA-256 31.6k, 24 substring checks about 11.2k
(24 x 7.3 x 64), zero-padding check 0.9k, document Poseidon hash 0.7k, three line-start
checks 0.4k.

The fixed part is the signing-input SHA and ECDSA (111k), the normalizers (65k), the
device key decode (61k), and the charset and length checks and constant pieces of the
lines (about 30k).

Projection (the fixture is 1,736 bytes and needs 28 padded blocks, so 1,792 minimum):

| maxDocLen | Constraints | Note |
|---|---|---|
| 1,792 | 1.52M | fixture size, no headroom |
| 2,240 | 1.83M | production setting (+25%) |
| 3,776 | about 2.90M | a 178-character `did:jwk`-style subject, plus 25% |

The 3,776 row ignores the larger `maxSubjLen` such a subject needs (the subject piece
and its charset check grow, roughly +10 per extra subject byte per line), which adds
well under 1%.

Other dimensions are cheap by comparison: each extra claim slot costs about
124k + 33k = 157k (a claim line plus a normalizer), most of it substring checks at the
chosen `maxDocLen`.

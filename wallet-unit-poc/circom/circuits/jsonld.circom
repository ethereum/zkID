pragma circom 2.2.3;

include "utils/es256.circom";
include "utils/utils.circom";
include "keyless_zk_proofs/hashtofield.circom";
include "keyless_zk_proofs/arrays.circom";
include "components/nquads-constants.circom";
include "components/nquads-subject.circom";
include "components/nquads-claim-line.circom";
include "components/jsonld-device-key.circom";
include "components/jsonld-value-normalizer.circom";

/// @title JSONLD
/// @notice OpenAC prepare circuit for an LD-signed JSON-LD credential.
///
/// The issuer signs, with a P-256 key, an RFC 7797 (b64=false) JWS over
///   ASCII(b64url('{"alg":"ES256","b64":false,"crit":["b64"]}') || ".") || proofHash || docHash
/// where docHash = SHA-256(canonical document N-Quads) and proofHash =
/// SHA-256(canonical proof-options N-Quads). This circuit:
///   1. hashes the (SHA-padded) document, builds the 121-byte signing input and
///      verifies the ECDSA-P256 signature against the public issuer key;
///   2. pins the credentialSubject IRI, the deviceKey line and every requested claim
///      line into the hashed document, byte for byte, at a line boundary;
///   3. decodes the device JWK and extracts the device key;
///   4. normalizes each requested claim value and derives its attribute identity.
///
/// RESIDUAL: proofHash is a private witness that is not recomputed, so the proof
/// options (created, verificationMethod, proofPurpose) are not checked here; the
/// signature only binds whatever proofHash the issuer signed.
///
/// PRECONDITIONS on the signed document (properties of what the issuer signed, not
/// of the witness; buildJsonLdPrepareInputs enforces them before inputs exist):
///   - exactly one credentialSubject line;
///   - each requested claim name, and `deviceKey`, occurs on exactly one line, as a
///     plain literal with no escapes;
///   - `"x":"` and `"y":"` each occur exactly once in the decoded device JWK.
///
/// @param maxDocLen   capacity of the SHA-padded document, a multiple of 64
/// @param maxClaims   claim slots; equals Show's nClaims
/// @param maxSubjLen  longest credentialSubject IRI
/// @param maxNameLen  longest claim name, at most Show's NAME_ID_LEN (31)
/// @param maxValueLen longest claim value, 64 (one SHA-256 block for digest64)
/// @param maxDeviceKeyLen longest base64url deviceKey literal, a multiple of 12, below 256
template JSONLD(
    maxDocLen,
    maxClaims,
    maxSubjLen,
    maxNameLen,
    maxValueLen,
    maxDeviceKeyLen
) {
    assert(maxDocLen % 64 == 0);
    assert(maxNameLen <= 31);
    assert(maxValueLen == 64);

    // The credential, hashed as the issuer hashed it: SHA-256 padding included, so
    // docLength is the padded length. Bytes past it are zero.
    signal input doc[maxDocLen];
    signal input docLength;
    // SHA-256 of the canonical proof-options N-Quads (private, not recomputed).
    signal input proofHash[32];

    signal input sig_r;
    signal input sig_s_inverse;
    // Issuer public key, public on the main component so a verifier can compare it
    // against the issuers it trusts.
    signal input pubKeyX;
    signal input pubKeyY;

    // credentialSubject IRI, shared by every pinned line.
    signal input subject[maxSubjLen];
    signal input subjectLength;
    signal input csPos;

    // deviceKey line and the JWK inside it.
    signal input deviceKeyLinePos;
    signal input deviceKeyValue[maxDeviceKeyLen];
    signal input deviceKeyValueLength;
    signal input jwkXPos;
    signal input jwkYPos;

    // Claim slots.
    signal input linePos[maxClaims];
    signal input names[maxClaims][maxNameLen];
    signal input nameLengths[maxClaims];
    signal input values[maxClaims][maxValueLen];
    signal input valueLengths[maxClaims];
    // claimFormats and claimFlags decide how each value in normalizedClaimValues was
    // produced, so they are public inputs of the main component: a verifier reading
    // those values needs them to know what the values mean.
    signal input claimFormats[maxClaims];   // 0=bool 1=uint 2=iso_date 3=roc_date 4=string 5=digest64
    signal input claimFlags[maxClaims];

    // Private, carried to Show through the shared witness (see mdoc.circom).
    signal normalizedClaimValues[maxClaims];
    signal claimIdentifierHashes[maxClaims];
    signal deviceKeyX;
    signal deviceKeyY;

    var DOC_BITS = log2Ceil(maxDocLen);

    // CHECK 1: the document hashes to the docHash the issuer signed.
    component docLengthBits = Num2Bits(DOC_BITS);
    docLengthBits.in <== docLength;
    component docLengthLe = LessEqThan(DOC_BITS + 1);
    docLengthLe.in[0] <== docLength;
    docLengthLe.in[1] <== maxDocLen;
    docLengthLe.out === 1;

    AssertZeroPadding(maxDocLen)(doc, docLength);
    signal docSha[256] <== Sha256Bytes(maxDocLen)(doc, docLength);

    signal docHashBytes[32];
    component docHashBits[32];
    for (var i = 0; i < 32; i++) {
        docHashBits[i] = Bits2Num(8);
        for (var k = 0; k < 8; k++) {
            docHashBits[i].in[7 - k] <== docSha[i * 8 + k];
        }
        docHashBytes[i] <== docHashBits[i].out;
    }

    // CHECK 2: ECDSA-P256 over SHA-256(header || "." || proofHash || docHash),
    // 121 bytes, which SHA-256 pads to three blocks (a block holds 55 bytes of
    // message, two hold 119). The padding is a circuit constant.
    var HDR_LEN = NQ_JWS_HDR_LEN();
    var MSG_LEN = HDR_LEN + 64;
    var PADDED_LEN = 192;
    assert(MSG_LEN == 121);

    CheckAreBytes(32)(proofHash);

    var HDR[HDR_LEN] = NQ_JWS_HDR();
    signal message[PADDED_LEN];
    for (var i = 0; i < HDR_LEN; i++) {
        message[i] <== HDR[i];
    }
    for (var i = 0; i < 32; i++) {
        message[HDR_LEN + i] <== proofHash[i];
        message[HDR_LEN + 32 + i] <== docHashBytes[i];
    }
    message[MSG_LEN] <== 128;
    for (var i = MSG_LEN + 1; i < PADDED_LEN - 2; i++) {
        message[i] <== 0;
    }
    // 121 bytes = 968 bits = 0x03C8, big-endian in the last bytes.
    message[PADDED_LEN - 2] <== 3;
    message[PADDED_LEN - 1] <== 200;

    ES256(PADDED_LEN)(message, PADDED_LEN, sig_r, sig_s_inverse, pubKeyX, pubKeyY);

    // CHECK 3: the true document length. The padded document is fixed by the
    // signature (SHA-256 collision resistance), so its last two bytes carry the
    // bit length n * 8 the issuer hashed. Every pinned line must end by n, so
    // nothing can be read out of the SHA padding, whose bytes are not text.
    signal lenHi <== SelectArrayValue(maxDocLen)(doc, docLength - 2, 1);
    signal lenLo <== SelectArrayValue(maxDocLen)(doc, docLength - 1, 1);
    signal docBitLen <== lenHi * 256 + lenLo;
    signal docEnd <-- docBitLen \ 8;
    docEnd * 8 === docBitLen;
    // 0x80 and the zero run take 1..64 bytes, then 8 bytes of length.
    signal padRun <== docLength - docEnd - 9;
    component padRunBits = Num2Bits(6);
    padRunBits.in <== padRun;

    signal docHash <== HashBytesToFieldWithLen(maxDocLen)(doc, docLength);

    // CHECK 4: the credentialSubject line pins the subject IRI.
    NQuadsSubject(maxDocLen, maxSubjLen)(doc, docHash, docEnd, subject, subjectLength, csPos);

    // CHECK 5: the deviceKey line, then the key inside its literal.
    var DK_NAME[9] = NQ_DEVICE_KEY_NAME();
    signal dkName[9];
    for (var i = 0; i < 9; i++) {
        dkName[i] <== DK_NAME[i];
    }
    NQuadsClaimLine(maxDocLen, maxSubjLen, 9, maxDeviceKeyLen)(
        doc, docHash, docEnd, subject, subjectLength, deviceKeyLinePos,
        dkName, 9, deviceKeyValue, deviceKeyValueLength, 1
    );
    (deviceKeyX, deviceKeyY) <== JsonLdDeviceKey(maxDeviceKeyLen)(
        deviceKeyValue, deviceKeyValueLength, jwkXPos, jwkYPos
    );

    // CHECK 6: per-claim line, identity and normalized value.
    // NAME_ID_LEN is the width Show hashes predicate names over (show.circom), so
    // both sides hash with the same template and the identities match by construction.
    var NAME_ID_LEN = 31;
    signal nameIdBytes[maxClaims][NAME_ID_LEN];
    signal nameHash[maxClaims];

    for (var i = 0; i < maxClaims; i++) {
        // claimFlags[i] must be 0 or 1; fractional values bypass gated assertions.
        claimFlags[i] * (1 - claimFlags[i]) === 0;

        NQuadsClaimLine(maxDocLen, maxSubjLen, maxNameLen, maxValueLen)(
            doc, docHash, docEnd, subject, subjectLength, linePos[i],
            names[i], nameLengths[i], values[i], valueLengths[i], claimFlags[i]
        );

        for (var j = 0; j < NAME_ID_LEN; j++) {
            if (j < maxNameLen) {
                nameIdBytes[i][j] <== names[i][j];
            } else {
                nameIdBytes[i][j] <== 0;
            }
        }
        nameHash[i] <== HashBytesToFieldWithLen(NAME_ID_LEN)(nameIdBytes[i], nameLengths[i]);
        claimIdentifierHashes[i] <== nameHash[i] * claimFlags[i];

        normalizedClaimValues[i] <== JsonLdValueNormalizer(maxValueLen)(
            values[i], valueLengths[i], claimFormats[i], claimFlags[i]
        );
    }
}

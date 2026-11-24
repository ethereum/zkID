pragma circom 2.2.3;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "@zk-email/circuits/utils/functions.circom";
include "@zk-email/circuits/utils/array.circom";
include "../keyless_zk_proofs/arrays.circom";
include "../keyless_zk_proofs/hashtofield.circom";
include "../utils/utils.circom";
include "ec-extractor.circom";

// Byte is one of [A-Za-z0-9_-], the base64url alphabet without padding.
template IsBase64UrlChar() {
    signal input in;
    signal output out;

    component digitLo = GreaterEqThan(8);
    digitLo.in[0] <== in;
    digitLo.in[1] <== 48;
    component digitHi = LessEqThan(8);
    digitHi.in[0] <== in;
    digitHi.in[1] <== 57;
    component upperLo = GreaterEqThan(8);
    upperLo.in[0] <== in;
    upperLo.in[1] <== 65;
    component upperHi = LessEqThan(8);
    upperHi.in[0] <== in;
    upperHi.in[1] <== 90;
    component lowerLo = GreaterEqThan(8);
    lowerLo.in[0] <== in;
    lowerLo.in[1] <== 97;
    component lowerHi = LessEqThan(8);
    lowerHi.in[0] <== in;
    lowerHi.in[1] <== 122;
    component dash = IsZero();
    dash.in <== in - 45;
    component under = IsZero();
    under.in <== in - 95;

    // The three ranges, '-' and '_' are disjoint, so the sum is already 0 or 1.
    signal isDigit <== digitLo.out * digitHi.out;
    signal isUpper <== upperLo.out * upperHi.out;
    signal isLower <== lowerLo.out * lowerHi.out;
    out <== isDigit + isUpper + isLower + dash.out + under.out;
}

// Decodes the deviceKey literal (base64url of a compact P-256 JWK) and extracts
// the device public key.
//
// `value` is the already-pinned literal body; this template only has to decode it
// and read the key out of the JSON. The reads use the same discipline as the JWT
// device-key path: `"x":"` and `"y":"` are circuit-constant anchors pinned at
// jwkXPos / jwkYPos in the decoded JSON, and each coordinate is then exactly the
// 43 base64url characters after its anchor, followed by the closing quote.
//
// PRECONDITION on the signed JWK: `"x":"` and `"y":"` each occur exactly once, so
// the anchors have a single possible position (checked by buildJsonLdPrepareInputs).
template JsonLdDeviceKey(maxDeviceKeyLen) {
    assert(maxDeviceKeyLen % 12 == 0);
    assert(maxDeviceKeyLen < 256);

    var maxDecoded = (maxDeviceKeyLen * 3) \ 4;

    signal input value[maxDeviceKeyLen];
    signal input valueLength;
    signal input jwkXPos;
    signal input jwkYPos;

    signal output deviceKeyX;
    signal output deviceKeyY;

    var LEN_BITS = log2Ceil(maxDeviceKeyLen + 1);
    var DEC_BITS = log2Ceil(maxDecoded + 1);

    component lenLe = LessEqThan(LEN_BITS);
    lenLe.in[0] <== valueLength;
    lenLe.in[1] <== maxDeviceKeyLen;
    lenLe.out === 1;

    component lenZero = IsZero();
    lenZero.in <== valueLength;
    lenZero.out === 0;

    component inRange[maxDeviceKeyLen];
    component isB64[maxDeviceKeyLen];
    for (var i = 0; i < maxDeviceKeyLen; i++) {
        inRange[i] = LessThan(LEN_BITS);
        inRange[i].in[0] <== i;
        inRange[i].in[1] <== valueLength;

        isB64[i] = IsBase64UrlChar();
        isB64[i].in <== value[i];
        inRange[i].out * (1 - isB64[i].out) === 0;
    }

    // DecodeSD maps every character at or past valueLength to '=', so the decoded
    // bytes past decodedLen are not data; they are zeroed below before use.
    component decode = DecodeSD(maxDeviceKeyLen, maxDecoded);
    decode.sdBytes <== value;
    decode.sdLen <== valueLength;

    // floor(3 * valueLength / 4): the number of whole bytes the characters carry.
    signal decodedLen <-- (3 * valueLength) \ 4;
    signal lenRemainder <== 3 * valueLength - 4 * decodedLen;
    component remBits = Num2Bits(2);
    remBits.in <== lenRemainder;

    component decInRange[maxDecoded];
    signal jwk[maxDecoded];
    for (var i = 0; i < maxDecoded; i++) {
        decInRange[i] = LessThan(DEC_BITS);
        decInRange[i].in[0] <== i;
        decInRange[i].in[1] <== decodedLen;
        jwk[i] <== decode.base64Out[i] * decInRange[i].out;
    }

    signal jwkHash <== HashBytesToFieldWithLen(maxDecoded)(jwk, decodedLen);

    signal anchorX[5];
    anchorX[0] <== 34;
    anchorX[1] <== 120;
    anchorX[2] <== 34;
    anchorX[3] <== 58;
    anchorX[4] <== 34;
    signal anchorY[5];
    anchorY[0] <== 34;
    anchorY[1] <== 121;
    anchorY[2] <== 34;
    anchorY[3] <== 58;
    anchorY[4] <== 34;

    component xPosBits = Num2Bits(DEC_BITS);
    xPosBits.in <== jwkXPos;
    component yPosBits = Num2Bits(DEC_BITS);
    yPosBits.in <== jwkYPos;

    CheckSubstrInclusionPoly(maxDecoded, 5)(jwk, jwkHash, anchorX, 5, jwkXPos, 1);
    CheckSubstrInclusionPoly(maxDecoded, 5)(jwk, jwkHash, anchorY, 5, jwkYPos, 1);

    // Each coordinate is 43 characters plus the closing quote, all inside the
    // decoded JSON; this keeps the extractor's 44-byte windows off the zeroed tail.
    signal xStart <== jwkXPos + 5;
    signal yStart <== jwkYPos + 5;
    component xEndLe = LessEqThan(DEC_BITS + 1);
    xEndLe.in[0] <== xStart + 44;
    xEndLe.in[1] <== decodedLen;
    xEndLe.out === 1;
    component yEndLe = LessEqThan(DEC_BITS + 1);
    yEndLe.in[0] <== yStart + 44;
    yEndLe.in[1] <== decodedLen;
    yEndLe.out === 1;

    signal xClose <== SelectArrayValue(maxDecoded)(jwk, xStart + 43, 1);
    xClose === 34;
    signal yClose <== SelectArrayValue(maxDecoded)(jwk, yStart + 43, 1);
    yClose === 34;

    component extractor = ECPublicKeyExtractor_Optimized(maxDecoded, 32);
    extractor.payload <== jwk;
    extractor.xStartIndex <== xStart;
    extractor.yStartIndex <== yStart;

    deviceKeyX <== extractor.pubKeyX;
    deviceKeyY <== extractor.pubKeyY;
}

pragma circom 2.2.3;

include "../jwt_tx_builder/bytes.circom";
include "../keyless_zk_proofs/arrays.circom";

// Every used disclosure digest must lie between quotes inside the unique _sd array.
// Keep this logic inside a component so its internal signals cannot move the
// parent JWT circuit's shared-witness values.
template BindSdDigestSpan(maxPayloadLength, maxMatches) {
    var maxClaims = maxMatches - 2;
    var SD_LEN = 7;

    signal input payload[maxPayloadLength];
    signal input matchIndex[maxMatches];
    signal input matchLength[maxMatches];
    signal input claimUsed[maxClaims];

    signal sdOpen[maxPayloadLength - SD_LEN + 1] <== PatternMatches(maxPayloadLength, SD_LEN, [34, 95, 115, 100, 34, 58, 91])(payload);
    var sdAnchors = 0;
    for (var j = 0; j < maxPayloadLength - SD_LEN + 1; j++) {
        sdAnchors += sdOpen[j];
    }
    signal sdAnchorCount <== sdAnchors;
    sdAnchorCount === 1;

    // sdQuote[j] = 1 if payload[j] is a '"' inside the _sd array (up to the first ']').
    signal isClose[maxPayloadLength];
    signal isQuote[maxPayloadLength];
    signal inSd[maxPayloadLength];
    signal sdQuote[maxPayloadLength];
    for (var j = 0; j < maxPayloadLength; j++) {
        isClose[j] <== IsEqual()([payload[j], 93]);
        isQuote[j] <== IsEqual()([payload[j], 34]);
        inSd[j] <== ((j > 0 ? inSd[j - 1] : 0) + (j >= SD_LEN ? sdOpen[j - SD_LEN] : 0)) * (1 - isClose[j]);
        sdQuote[j] <== inSd[j] * isQuote[j];
    }

    signal digestOpenIdx[maxClaims];
    signal digestCloseIdx[maxClaims];
    signal digestOpenOk[maxClaims];
    signal digestCloseOk[maxClaims];
    for (var i = 0; i < maxClaims; i++) {
        // The quotes around the digest must be inside _sd. Unused slots read index 0.
        digestOpenIdx[i] <== claimUsed[i] * (matchIndex[i + 2] - 1);
        digestCloseIdx[i] <== claimUsed[i] * (matchIndex[i + 2] + matchLength[i + 2]);
        digestOpenOk[i] <== SelectArrayValue(maxPayloadLength)(sdQuote, digestOpenIdx[i], claimUsed[i]);
        digestCloseOk[i] <== SelectArrayValue(maxPayloadLength)(sdQuote, digestCloseIdx[i], claimUsed[i]);
        claimUsed[i] * (1 - digestOpenOk[i]) === 0;
        claimUsed[i] * (1 - digestCloseOk[i]) === 0;
    }
}

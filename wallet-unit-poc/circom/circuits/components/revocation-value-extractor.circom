pragma circom 2.2.3;

include "circomlib/circuits/comparators.circom";
include "../utils/utils.circom";

/// @title RevocationValueExtractor
/// @notice Reads `"revocation_value":"<43 base64url chars>"` starting at `index`
///         in the decoded JWT payload and outputs the 32-byte revocation value as
///         [hi, lo] 128-bit limbs.
/// @notice The anchor bytes and the closing quote are pinned here, so the prover only
///         chooses the position. The anchor must occur once in the signed payload.
template RevocationValueExtractor(maxPayloadLength) {
    var ANCHOR_LEN = 20;
    // "revocation_value":"
    var ANCHOR[ANCHOR_LEN] = [34, 114, 101, 118, 111, 99, 97, 116, 105, 111, 110, 95,
                              118, 97, 108, 117, 101, 34, 58, 34];
    var VALUE_LEN = 43;
    var WINDOW_LEN = ANCHOR_LEN + VALUE_LEN + 1;

    signal input payload[maxPayloadLength];
    signal input index;

    signal output out[2];

    // VarShiftLeft wraps around, so keep the window inside the payload.
    component inBounds = LessEqThan(log2Ceil(maxPayloadLength) + 1);
    inBounds.in[0] <== index + WINDOW_LEN;
    inBounds.in[1] <== maxPayloadLength;
    inBounds.out === 1;

    signal window[WINDOW_LEN] <== VarShiftLeft(maxPayloadLength, WINDOW_LEN)(payload, index);

    for (var i = 0; i < ANCHOR_LEN; i++) {
        window[i] === ANCHOR[i];
    }
    window[WINDOW_LEN - 1] === 34;

    signal value[VALUE_LEN + 1];
    for (var i = 0; i < VALUE_LEN; i++) {
        value[i] <== window[ANCHOR_LEN + i];
    }
    value[VALUE_LEN] <== 0;

    component decode = DecodeSD(VALUE_LEN + 1, 32);
    decode.sdBytes <== value;
    decode.sdLen <== VALUE_LEN;

    component hi = BytesToNumberBE(16);
    component lo = BytesToNumberBE(16);
    for (var i = 0; i < 16; i++) {
        hi.in[i] <== decode.base64Out[i];
        lo.in[i] <== decode.base64Out[16 + i];
    }

    out[0] <== hi.out;
    out[1] <== lo.out;
}

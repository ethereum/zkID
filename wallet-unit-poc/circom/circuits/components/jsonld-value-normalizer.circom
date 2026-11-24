pragma circom 2.2.3;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "@zk-email/circuits/lib/sha.circom";
include "claim-value-normalizer.circom";

/// @title JsonLdValueNormalizer
/// @notice ClaimValueNormalizer formats 0..4 plus format 5 = digest64.
/// @notice digest64 is the low 64 bits of SHA-256(value), read as a big-endian
///         256-bit integer, so it fits Show's 64-bit predicate operands. It lets a
///         predicate compare a string longer than the 8-byte string packing
///         (e.g. nationality == "Ruritanian") by equality on the digest.
/// @param maxValueLen must be 64: the digest hashes one SHA-256 block.
/// @input value: value bytes, zero past valueLength (forced by the caller's substring match)
/// @input valueLength: number of value bytes
/// @input format: 0=bool, 1=uint, 2=iso_date, 3=roc_date, 4=string, 5=digest64
/// @input enabled: 0 or 1; a disabled slot normalizes to 0 whatever it holds
template JsonLdValueNormalizer(maxValueLen) {
    assert(maxValueLen == 64);

    signal input value[maxValueLen];
    signal input valueLength;
    signal input format;
    signal input enabled;

    signal output normalizedValue;

    component formatEq[6];
    signal formatSum[7];
    formatSum[0] <== 0;
    for (var i = 0; i < 6; i++) {
        formatEq[i] = IsEqual();
        formatEq[i].in[0] <== format;
        formatEq[i].in[1] <== i;
        formatSum[i + 1] <== formatSum[i] + formatEq[i].out;
    }
    // Exactly one format (0..5) for an active slot. Written as an equality on the
    // IsEqual outputs rather than a range check, so there is no field-wrap case.
    enabled * (1 - formatSum[6]) === 0;

    signal isDigest <== formatEq[5].out;

    // Format 5 and disabled slots hand the base normalizer format 0 (bool), which
    // has no constraints on the value bytes.
    signal formatActive <== format * enabled;
    signal baseFormat <== formatActive * (1 - isDigest);

    component base = ClaimValueNormalizer(maxValueLen);
    base.value <== value;
    base.valueLength <== valueLength;
    base.format <== baseFormat;

    // One SHA-256 block, every byte pinned: value, the 0x80 marker at index
    // valueLength, zeros, then the big-endian bit length. Nothing here is a
    // prover input, so the hashed message cannot be padded differently from
    // the value. 55 message bytes + 0x80 + 8 length bytes = 64.
    signal isDigestActive <== isDigest * enabled;
    component lenLe55 = LessEqThan(7);
    lenLe55.in[0] <== valueLength;
    lenLe55.in[1] <== 55;
    isDigestActive * (1 - lenLe55.out) === 0;

    component atLen[56];
    signal block[64];
    for (var i = 0; i < 56; i++) {
        atLen[i] = IsEqual();
        atLen[i].in[0] <== valueLength;
        atLen[i].in[1] <== i;
        block[i] <== value[i] + 128 * atLen[i].out;
    }
    for (var i = 56; i < 62; i++) {
        block[i] <== 0;
    }
    // valueLength <= 64 (caller), so the bit length is below 2^10.
    component lenBits = Num2Bits(10);
    lenBits.in <== valueLength * 8;
    var loByte = 0;
    for (var k = 0; k < 8; k++) {
        loByte += lenBits.out[k] * (1 << k);
    }
    block[62] <== lenBits.out[8] + 2 * lenBits.out[9];
    block[63] <== loByte;

    signal digestBits[256] <== Sha256Bytes(64)(block, 64);
    component digestLow64 = Bits2Num(64);
    for (var i = 0; i < 64; i++) {
        digestLow64.in[i] <== digestBits[255 - i];
    }

    signal baseValue <== (1 - isDigest) * base.normalizedValue;
    signal digestValue <== isDigest * digestLow64.out;
    signal raw <== baseValue + digestValue;
    normalizedValue <== raw * enabled;
}

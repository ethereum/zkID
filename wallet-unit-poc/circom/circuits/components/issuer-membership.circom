pragma circom 2.2.3;

include "circomlib/circuits/sha256/sha256.circom";
include "@zk-kit/binary-merkle-root-sha256.circom/src/binary-merkle-root-sha256.circom";

/// @title AnchoredNum2Bits
/// @notice Num2Bits(n) for a non-zero input, bound through its inverse.
/// Only quadratic constraints touch `in`, so -O2 keeps it as a witness signal,
/// which the shared-witness binding needs.
template AnchoredNum2Bits(n) {
    signal input in;
    signal output out[n];

    signal inv <-- in != 0 ? 1 / in : 0;
    in * inv === 1;

    var lc = 0;
    for (var i = 0; i < n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] - 1) === 0;
        lc += out[i] * (1 << i);
    }
    // lc * inv = in * inv = 1 with inv != 0, so lc = in.
    lc * inv === 1;
}

/// @title IssuerCommitment
/// @notice sha256(be32(x) || be32(y)) as [hi, lo] 128-bit limbs.
/// Matches `sha256Hash2(x, y)` in @coordination-network/issuer-registry.
template IssuerCommitment() {
    signal input pubKeyX;
    signal input pubKeyY;
    signal output out[2];

    // Non-canonical bits only change the digest, so they can't forge membership.
    component xBits = AnchoredNum2Bits(256);
    xBits.in <== pubKeyX;
    component yBits = AnchoredNum2Bits(256);
    yBits.in <== pubKeyY;

    component hash = Sha256(512);
    for (var i = 0; i < 256; i++) {
        hash.in[i] <== xBits.out[255 - i];
        hash.in[256 + i] <== yBits.out[255 - i];
    }

    out <== BinaryMerkleRootSha256BitsToLimbs()(hash.out);
}

/// @title IssuerMembership
/// @notice Proves the issuer key is in a SHA-256 LeanIMT and outputs the root as [hi, lo] limbs.
/// The leaf is derived from the key, never taken as input: LeanIMT leaves are unhashed,
/// so a free leaf could be an internal node.
template IssuerMembership(maxDepth) {
    signal input pubKeyX;
    signal input pubKeyY;
    signal input depth;
    signal input index;
    signal input siblings[maxDepth][2];
    signal output root[2];

    signal leaf[2] <== IssuerCommitment()(pubKeyX, pubKeyY);
    root <== BinaryMerkleRootSha256(maxDepth)(leaf, depth, index, siblings);
}

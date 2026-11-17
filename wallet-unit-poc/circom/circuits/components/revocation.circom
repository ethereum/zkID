pragma circom 2.2.3;

include "circomlib/circuits/sha256/sha256.circom";
include "circomlib/circuits/comparators.circom";
include "@zk-kit/lean-imt-plus-sha256.circom/src/lean-imt-plus-sha256.circom";

/// @title RevocationCheck
/// @notice Proves `commitment == sha256(secret)` and that `commitment` is not in the
///         LeanIMT+ (SHA-256) tree of revoked commitments.
/// @notice Every 256-bit value is a pair of 128-bit limbs [hi, lo].
/// @notice Outputs the tree root, or [0, 0] for an empty registry (depth 0), which
///         is the root the registry reports while empty.
/// @param MAX_DEPTH maximum tree depth
template RevocationCheck(MAX_DEPTH) {
    signal input secret[2];
    signal input commitment[2];
    signal input leafValue[2];
    signal input leafNextValue[2];
    signal input leafIndex;
    signal input depth;
    signal input siblings[MAX_DEPTH][2];

    signal output root[2];

    component secretBits = LeanIMTPlusSha256LimbsToBits();
    secretBits.in <== secret;

    component hash = Sha256(256);
    hash.in <== secretBits.out;

    component digest = LeanIMTPlusSha256BitsToLimbs();
    digest.in <== hash.out;

    commitment[0] === digest.out[0];
    commitment[1] === digest.out[1];

    component tree = LeanIMTPlusSha256(MAX_DEPTH);
    tree.proofType <== 1;
    tree.value <== commitment;
    tree.leafValue <== leafValue;
    tree.leafNextValue <== leafNextValue;
    tree.leafIndex <== leafIndex;
    tree.depth <== depth;
    tree.siblings <== siblings;

    signal isEmpty <== IsZero()(depth);
    root[0] <== (1 - isEmpty) * tree.out[0];
    root[1] <== (1 - isEmpty) * tree.out[1];
}

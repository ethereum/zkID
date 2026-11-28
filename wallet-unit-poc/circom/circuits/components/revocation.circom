pragma circom 2.2.3;

include "circomlib/circuits/sha256/sha256.circom";
include "circomlib/circuits/comparators.circom";
include "@zk-kit/lean-imt-plus-sha256.circom/src/lean-imt-plus-sha256.circom";

/// @title AnchoredLimbsToBits
/// @notice [hi, lo] 128-bit limbs to big-endian bits, like LeanIMTPlusSha256LimbsToBits,
///         for limbs that may be zero.
/// @notice Each limb is tied to its bits only through quadratic constraints, scaled by a
///         non-zero witness k, so -O2 keeps the limbs as witness signals. The shared-witness
///         binding needs that.
template AnchoredLimbsToBits() {
    signal input in[2];
    signal output out[256];

    signal k <-- 1;
    signal kInv <-- 1;
    k * kInv === 1;

    signal limbBits[2][128];
    for (var l = 0; l < 2; l++) {
        var lc = 0;
        for (var i = 0; i < 128; i++) {
            limbBits[l][i] <-- (in[l] >> i) & 1;
            limbBits[l][i] * (limbBits[l][i] - 1) === 0;
            lc += limbBits[l][i] * (1 << i);
        }
        // k != 0, so lc = in[l].
        (lc - in[l]) * k === 0;
    }

    for (var i = 0; i < 128; i++) {
        out[i] <== limbBits[0][127 - i];
        out[128 + i] <== limbBits[1][127 - i];
    }
}

/// @title RevocationCommitment
/// @notice v_rev = sha256(be32(x) || be32(y) || be32(r) || be32(3)) as [hi, lo] limbs,
///         binding the issuer-signed revocation value r to the issuer key (x, y).
/// @notice The trailing tag 3 makes the hash input 1024 bits, unlike LeanIMT+ leaves (768)
///         and nodes (512), and leaves tags 0 to 2 for other commitments.
/// @notice `issuerKeyBits` must be the canonical be32(x) || be32(y), as IssuerKeyBits
///         outputs it. A second encoding of the same key would give a second commitment.
template RevocationCommitment() {
    var TAG = 3;

    signal input issuerKeyBits[512];
    signal input value[2];
    signal output out[2];

    // Range-checks both limbs to 128 bits, so the value has one encoding.
    component valueBits = AnchoredLimbsToBits();
    valueBits.in <== value;

    component hash = Sha256(1024);
    for (var i = 0; i < 512; i++) {
        hash.in[i] <== issuerKeyBits[i];
    }
    for (var i = 0; i < 256; i++) {
        hash.in[512 + i] <== valueBits.out[i];
        hash.in[768 + i] <== (TAG >> (255 - i)) & 1;
    }

    out <== LeanIMTPlusSha256BitsToLimbs()(hash.out);
}

/// @title RevocationCheck
/// @notice Proves the credential's revocation commitment (see RevocationCommitment) is not in the
///         LeanIMT+ (SHA-256) tree of revoked commitments.
/// @notice Every 256-bit value is a pair of 128-bit limbs [hi, lo].
/// @notice Outputs the tree root, or [0, 0] for an empty registry (depth 0), which
///         is the root the registry reports while empty.
/// @param MAX_DEPTH maximum tree depth
template RevocationCheck(MAX_DEPTH) {
    signal input issuerKeyBits[512];
    signal input value[2];
    signal input leafValue[2];
    signal input leafNextValue[2];
    signal input leafIndex;
    signal input depth;
    signal input siblings[MAX_DEPTH][2];

    signal output root[2];

    signal commitment[2] <== RevocationCommitment()(issuerKeyBits, value);

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

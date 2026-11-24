pragma circom 2.2.3;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "@zk-email/circuits/utils/functions.circom";
include "@zk-email/circuits/utils/array.circom";
include "../keyless_zk_proofs/arrays.circom";
include "nquads-constants.circom";

// Pins `subject` into the signed N-Quads as the object of the credentialSubject
// line:  _:<label> <https://www.w3.org/2018/credentials#credentialSubject> <SUBJECT> .\n
//
// Everything from the space before `<https:` to the line feed is pinned. The blank
// node label before it is not, which is harmless: what the claim lines need is the
// subject IRI, and `subject` is forced to be exactly that IRI because the closing
// `> .\n` is pinned right after it and the IRI alphabet below excludes `>`.
//
// PRECONDITION on the signed document: the credentialSubject predicate occurs on
// exactly one line, so csPos has a single possible value. The bytes are fixed by
// the issuer signature, so this is a property of what the issuer signed, enforced
// by buildJsonLdPrepareInputs() before inputs are built.
template NQuadsSubject(maxDocLen, maxSubjLen) {
    signal input doc[maxDocLen];
    signal input docHash;
    // Length of the unpadded document the issuer hashed.
    signal input docEnd;
    signal input subject[maxSubjLen];
    signal input subjectLength;
    signal input csPos;

    var PREFIX_LEN = NQ_CS_PREFIX_LEN();
    var POS_BITS = log2Ceil(maxDocLen + 1);
    var END_BITS = log2Ceil(maxDocLen + maxSubjLen + PREFIX_LEN + 8) + 1;

    component subjLenLe = LessEqThan(log2Ceil(maxSubjLen + 1));
    subjLenLe.in[0] <== subjectLength;
    subjLenLe.in[1] <== maxSubjLen;
    subjLenLe.out === 1;

    component subjLenZero = IsZero();
    subjLenZero.in <== subjectLength;
    subjLenZero.out === 0;

    // Bytes past subjectLength are forced to 0 by the substring match, so the
    // excluded set (all non-zero) can be checked over the whole array.
    var BAD[7] = [60, 62, 32, 34, 92, 10, 13];
    component badEq[maxSubjLen][7];
    for (var i = 0; i < maxSubjLen; i++) {
        var badSum = 0;
        for (var k = 0; k < 7; k++) {
            badEq[i][k] = IsZero();
            badEq[i][k].in <== subject[i] - BAD[k];
            badSum += badEq[i][k].out;
        }
        badSum === 0;
    }

    component posBits = Num2Bits(POS_BITS);
    posBits.in <== csPos;

    signal prefix[PREFIX_LEN];
    var CS_PREFIX[PREFIX_LEN] = NQ_CS_PREFIX();
    for (var i = 0; i < PREFIX_LEN; i++) {
        prefix[i] <== CS_PREFIX[i];
    }
    signal tail[4];
    tail[0] <== 62;
    tail[1] <== 32;
    tail[2] <== 46;
    tail[3] <== 10;

    CheckSubstrInclusionPoly(maxDocLen, PREFIX_LEN)(doc, docHash, prefix, PREFIX_LEN, csPos, 1);

    signal subjPos <== csPos + PREFIX_LEN;
    CheckSubstrInclusionPoly(maxDocLen, maxSubjLen)(doc, docHash, subject, subjectLength, subjPos, 1);

    signal tailPos <== subjPos + subjectLength;
    CheckSubstrInclusionPoly(maxDocLen, 4)(doc, docHash, tail, 4, tailPos, 1);

    component endLe = LessEqThan(END_BITS);
    endLe.in[0] <== tailPos + 4;
    endLe.in[1] <== docEnd;
    endLe.out === 1;
}

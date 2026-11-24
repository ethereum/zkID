pragma circom 2.2.3;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "@zk-email/circuits/utils/functions.circom";
include "@zk-email/circuits/utils/array.circom";
include "../keyless_zk_proofs/arrays.circom";
include "nquads-constants.circom";

// Byte is one of [A-Za-z0-9_].
template IsNameChar() {
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
    component under = IsZero();
    under.in <== in - 95;

    // The three ranges and '_' are disjoint, so the sum is already 0 or 1.
    signal isDigit <== digitLo.out * digitHi.out;
    signal isUpper <== upperLo.out * upperHi.out;
    signal isLower <== lowerLo.out * lowerHi.out;
    out <== isDigit + isUpper + isLower + under.out;
}

// Line start: position 0, or the byte before it is a line feed. Literals in
// canonical N-Quads cannot contain a raw line feed, so a position that follows
// one is a real line boundary and cannot sit inside another claim's value.
template AssertLineStart(maxDocLen) {
    signal input doc[maxDocLen];
    signal input pos;
    signal input enabled;

    component isFirst = IsZero();
    isFirst.in <== pos;

    // pos 0 reads index 0, whose value is then ignored.
    signal prev <== SelectArrayValue(maxDocLen)(doc, pos - 1 + isFirst.out, enabled);
    signal needsLf <== enabled * (1 - isFirst.out);
    needsLf * (prev - 10) === 0;
}

// CheckSubstrInclusionPoly over `piece[0..len)` at `pos`, only when enabled. A
// disabled piece is aimed at (0, 0), the one window the primitive accepts as an
// empty match, so inactive slots carry no constraints on their unused inputs.
template CheckPieceAt(maxDocLen, maxPieceLen) {
    signal input doc[maxDocLen];
    signal input docHash;
    signal input piece[maxPieceLen];
    signal input len;
    signal input pos;
    signal input enabled;

    signal gatedPos <== pos * enabled;
    signal gatedLen <== len * enabled;
    CheckSubstrInclusionPoly(maxDocLen, maxPieceLen)(doc, docHash, piece, gatedLen, gatedPos, enabled);
}

// One claim triple, pinned byte for byte in the signed N-Quads:
//
//   <SUBJECT> <https://example.org/eid#NAME> "VALUE" .\n
//
// starting at a line boundary. Every structural byte is a circuit constant; the
// variable parts are the shared subject, the name and the value, each pinned to
// the document at a position derived from `pos`, so there is a single window to
// aim and nothing to re-point. NAME is [A-Za-z0-9_]+ and VALUE has no quote,
// backslash or line break, so neither can swallow the delimiters around it, and a
// plain literal (no datatype or language tag) is the only form that matches.
//
// All checks are gated by `enabled` (assumed boolean, constrained by the caller).
template NQuadsClaimLine(maxDocLen, maxSubjLen, maxNameLen, maxValueLen) {
    signal input doc[maxDocLen];
    signal input docHash;
    signal input docEnd;
    signal input subject[maxSubjLen];
    signal input subjectLength;
    signal input pos;
    signal input name[maxNameLen];
    signal input nameLength;
    signal input value[maxValueLen];
    signal input valueLength;
    signal input enabled;

    var BASE_LEN = NQ_BASE_LEN();
    var MID_LEN = 3 + BASE_LEN;
    var POS_BITS = log2Ceil(maxDocLen + 1);
    var END_BITS = log2Ceil(maxDocLen + maxSubjLen + maxNameLen + maxValueLen + MID_LEN + 16) + 1;

    component posBits = Num2Bits(POS_BITS);
    posBits.in <== pos;

    component nameLenLe = LessEqThan(log2Ceil(maxNameLen + 1));
    nameLenLe.in[0] <== nameLength;
    nameLenLe.in[1] <== maxNameLen;
    nameLenLe.out === 1;

    component valueLenLe = LessEqThan(log2Ceil(maxValueLen + 1));
    valueLenLe.in[0] <== valueLength;
    valueLenLe.in[1] <== maxValueLen;
    valueLenLe.out === 1;

    // The substring primitive needs a non-empty window.
    component nameLenZero = IsZero();
    nameLenZero.in <== nameLength;
    enabled * nameLenZero.out === 0;
    component valueLenZero = IsZero();
    valueLenZero.in <== valueLength;
    enabled * valueLenZero.out === 0;

    AssertLineStart(maxDocLen)(doc, pos, enabled);

    // Constant pieces.
    signal open[1];
    open[0] <== 60;
    signal mid[MID_LEN];
    mid[0] <== 62;
    mid[1] <== 32;
    mid[2] <== 60;
    var BASE[BASE_LEN] = NQ_BASE();
    for (var i = 0; i < BASE_LEN; i++) {
        mid[3 + i] <== BASE[i];
    }
    signal quoteOpen[3];
    quoteOpen[0] <== 62;
    quoteOpen[1] <== 32;
    quoteOpen[2] <== 34;
    signal lineEnd[4];
    lineEnd[0] <== 34;
    lineEnd[1] <== 32;
    lineEnd[2] <== 46;
    lineEnd[3] <== 10;

    signal subjPos <== pos + 1;
    signal midPos <== subjPos + subjectLength;
    signal namePos <== midPos + MID_LEN;
    signal quoteOpenPos <== namePos + nameLength;
    signal valuePos <== quoteOpenPos + 3;
    signal lineEndPos <== valuePos + valueLength;

    CheckPieceAt(maxDocLen, 1)(doc, docHash, open, 1, pos, enabled);
    CheckPieceAt(maxDocLen, maxSubjLen)(doc, docHash, subject, subjectLength, subjPos, enabled);
    CheckPieceAt(maxDocLen, MID_LEN)(doc, docHash, mid, MID_LEN, midPos, enabled);
    CheckPieceAt(maxDocLen, maxNameLen)(doc, docHash, name, nameLength, namePos, enabled);
    CheckPieceAt(maxDocLen, 3)(doc, docHash, quoteOpen, 3, quoteOpenPos, enabled);
    CheckPieceAt(maxDocLen, maxValueLen)(doc, docHash, value, valueLength, valuePos, enabled);
    CheckPieceAt(maxDocLen, 4)(doc, docHash, lineEnd, 4, lineEndPos, enabled);

    // The whole line is inside the unpadded document, so no piece reads SHA padding.
    component endLe = LessEqThan(END_BITS);
    endLe.in[0] <== lineEndPos + 4;
    endLe.in[1] <== docEnd;
    (1 - endLe.out) * enabled === 0;

    component inName[maxNameLen];
    component isNameChar[maxNameLen];
    signal nameActive[maxNameLen];
    for (var i = 0; i < maxNameLen; i++) {
        inName[i] = LessThan(log2Ceil(maxNameLen + 1));
        inName[i].in[0] <== i;
        inName[i].in[1] <== nameLength;
        nameActive[i] <== enabled * inName[i].out;

        isNameChar[i] = IsNameChar();
        isNameChar[i].in <== name[i];
        nameActive[i] * (1 - isNameChar[i].out) === 0;
    }

    // Bytes past valueLength are zero (forced by the substring match), and the
    // excluded bytes are non-zero, so no length mask is needed.
    var BAD[4] = [34, 92, 10, 13];
    component badEq[maxValueLen][4];
    for (var i = 0; i < maxValueLen; i++) {
        var badSum = 0;
        for (var k = 0; k < 4; k++) {
            badEq[i][k] = IsZero();
            badEq[i][k].in <== value[i] - BAD[k];
            badSum += badEq[i][k].out;
        }
        enabled * badSum === 0;
    }
}

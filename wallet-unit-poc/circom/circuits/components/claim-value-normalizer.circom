pragma circom 2.2.3;

include "circomlib/circuits/comparators.circom";
include "../utils/utils.circom";

/// @title ClaimValueNormalizer
/// @notice Converts extracted claim value bytes to a canonical integer.
/// @param valueLen: maximum length of value bytes
/// @input value: array of extracted value bytes (ASCII)
/// @input valueLength: actual number of meaningful bytes
/// @input isActive: 1 for a decoded slot. Unused slots carry an empty value under whatever
///        format the builder defaults to (uint), so the emptiness and spelling checks below
///        apply only to active slots.
/// @input format: 0=bool (1|true|0|false), 1=uint, 2=iso_date (YYYY-MM-DD), 3=roc_date (YYYMMDD), 4=string (big-endian byte pack)
/// @output normalizedValue: single integer representation suitable for numeric comparison
template ClaimValueNormalizer(valueLen) {
    signal input value[valueLen];
    signal input valueLength;
    signal input format;
    signal input isActive;

    signal output normalizedValue;

    // ===== Format selectors =====
    component formatEq[5];
    signal isBoolFormat;
    signal isUintFormat;
    signal isIsoDateFormat;
    signal isRocDateFormat;

    for (var i = 0; i < 5; i++) {
        formatEq[i] = IsEqual();
        formatEq[i].in[0] <== format;
        formatEq[i].in[1] <== i;
    }

    isBoolFormat    <== formatEq[0].out;
    isUintFormat    <== formatEq[1].out;
    isIsoDateFormat <== formatEq[2].out;
    isRocDateFormat <== formatEq[3].out;
    signal isStringFormat <== formatEq[4].out;

    // Require exactly one supported format (0..4) to be selected, so an
    // out-of-range format is rejected rather than normalized to 0.
    signal formatSelectorSum <== isBoolFormat + isUintFormat + isIsoDateFormat + isRocDateFormat + isStringFormat;
    formatSelectorSum === 1;

    // ===== Format 0: Boolean — "1"/"true" → 1, "0"/"false" → 0, anything else unsatisfiable =====
    component valLenEq1 = IsEqual();
    valLenEq1.in[0] <== valueLength;
    valLenEq1.in[1] <== 1;

    component valLenEq4 = IsEqual();
    valLenEq4.in[0] <== valueLength;
    valLenEq4.in[1] <== 4;

    component valLenEq5 = IsEqual();
    valLenEq5.in[0] <== valueLength;
    valLenEq5.in[1] <== 5;

    component v0is1 = IsEqual();
    v0is1.in[0] <== value[0];
    v0is1.in[1] <== 49; // '1'

    component v0is0 = IsEqual();
    v0is0.in[0] <== value[0];
    v0is0.in[1] <== 48; // '0'

    component vt = IsEqual(); vt.in[0] <== value[0]; vt.in[1] <== 116; // 't'
    component vr = IsEqual(); vr.in[0] <== value[1]; vr.in[1] <== 114; // 'r'
    component vu = IsEqual(); vu.in[0] <== value[2]; vu.in[1] <== 117; // 'u'
    component ve = IsEqual(); ve.in[0] <== value[3]; ve.in[1] <== 101; // 'e'

    component vf  = IsEqual(); vf.in[0]  <== value[0]; vf.in[1]  <== 102; // 'f'
    component va  = IsEqual(); va.in[0]  <== value[1]; va.in[1]  <== 97;  // 'a'
    component vl  = IsEqual(); vl.in[0]  <== value[2]; vl.in[1]  <== 108; // 'l'
    component vs  = IsEqual(); vs.in[0]  <== value[3]; vs.in[1]  <== 115; // 's'
    component ve5 = IsEqual(); ve5.in[0] <== value[4]; ve5.in[1] <== 101; // 'e'

    signal valueTrueWordLeft  <== vt.out * vr.out;
    signal valueTrueWordRight <== vu.out * ve.out;
    signal valueTrueWord      <== valueTrueWordLeft * valueTrueWordRight;

    signal valueFalseWordLeft  <== vf.out * va.out;
    signal valueFalseWordRight <== vl.out * vs.out;
    signal valueFalseWordHead  <== valueFalseWordLeft * valueFalseWordRight;
    signal valueFalseWord      <== valueFalseWordHead * ve5.out;

    signal boolValueFromOne  <== valLenEq1.out * v0is1.out;
    signal boolValueFromWord <== valLenEq4.out * valueTrueWord;
    signal boolValue <== boolValueFromOne + boolValueFromWord;
    signal boolFalseFromZero <== valLenEq1.out * v0is0.out;
    signal boolFalseFromWord <== valLenEq5.out * valueFalseWord;

    // The four spellings differ in length or first byte, so at most one term
    // is 1 and the sum is a boolean.
    signal activeBool <== isActive * isBoolFormat;
    activeBool * (1 - boolValue - boolFalseFromZero - boolFalseFromWord) === 0;

    // ===== Format 1: Unsigned Integer — decimal ASCII → integer =====
    signal uintAccum[valueLen + 1];
    uintAccum[0] <== 0;

    // Scale by 10 only within valueLength; past the value the multiplier is 1
    // so trailing padding does not inflate the result.
    component valueLenGt[valueLen];
    signal uintScaled[valueLen];
    for (var i = 0; i < valueLen; i++) {
        valueLenGt[i] = GreaterThan(log2Ceil(valueLen + 1));
        valueLenGt[i].in[0] <== valueLength;
        valueLenGt[i].in[1] <== i;

        uintScaled[i] <== uintAccum[i] * (9 * valueLenGt[i].out + 1);
        uintAccum[i + 1] <== uintScaled[i] + (value[i] - 48) * valueLenGt[i].out;
    }
    signal uintValue <== uintAccum[valueLen];

    // An empty value activates no digit constraints and leaves the
    // accumulator at 0, which would read as a signed zero.
    signal activeUint <== isActive * isUintFormat;
    activeUint * (1 - valueLenGt[0].out) === 0;

    // The accumulator is field arithmetic, so without the two checks below an
    // over-long decimal (>= 77 digits) or a non-digit byte wraps mod q and
    // aliases a large signed value onto a small residue, which then satisfies
    // a comparison it should fail. Bounding the digit count keeps every
    // partial product under 10^19 - 1 < 2^64 < q, and the digit checks keep
    // each term in [0, 9]. Together they make EvalPredicate's documented
    // [0, 2^VALUE_BITS) precondition hold rather than be assumed.
    var maxUintDigits = valueLen < 19 ? valueLen : 19;

    component uintLenLe = LessEqThan(log2Ceil(valueLen + 1));
    uintLenLe.in[0] <== valueLength;
    uintLenLe.in[1] <== maxUintDigits;
    isUintFormat * (1 - uintLenLe.out) === 0;

    // Slots at or past maxUintDigits are inactive under the bound above, so
    // only the leading slots need digit checks.
    component digitGe48[maxUintDigits];
    component digitLe57[maxUintDigits];
    signal digitActive[maxUintDigits];
    for (var i = 0; i < maxUintDigits; i++) {
        digitActive[i] <== isUintFormat * valueLenGt[i].out;

        digitGe48[i] = GreaterEqThan(9);
        digitGe48[i].in[0] <== value[i];
        digitGe48[i].in[1] <== 48;

        digitLe57[i] = LessEqThan(9);
        digitLe57[i].in[0] <== value[i];
        digitLe57[i].in[1] <== 57;

        digitActive[i] * (1 - digitGe48[i].out) === 0;
        digitActive[i] * (1 - digitLe57[i].out) === 0;
    }

    // ===== Format 2: ISO Date (YYYY-MM-DD) → YYYYMMDD integer =====
    signal isoDateValue <==
        ((value[0] - 48) * 1000 + (value[1] - 48) * 100 + (value[2] - 48) * 10 + (value[3] - 48)) * 10000
        + ((value[5] - 48) * 10 + (value[6] - 48)) * 100
        + ((value[8] - 48) * 10 + (value[9] - 48));

    // ===== Format 3: ROC Date (YYYMMDD) → integer =====
    signal rocDateValue <==
        ((value[0] - 48) * 100 + (value[1] - 48) * 10 + (value[2] - 48)) * 10000
        + ((value[3] - 48) * 10 + (value[4] - 48)) * 100
        + ((value[5] - 48) * 10 + (value[6] - 48));

    // Both date branches read fixed byte positions, so they need the same two
    // checks the uint branch has. The extractor zero-masks bytes past
    // valueLength, so a short value makes every unread slot contribute
    // (0 - 48) = q - 48 and the branch normalizes to a huge negative residue --
    // which satisfies LessEqThan(64) against ANY comparison value, including 0.
    // Pinning the exact width and the digit alphabet keeps the result in
    // [0, 99999999], well inside EvalPredicate's [0, 2^VALUE_BITS) precondition.
    component isoLenEq = IsEqual();
    isoLenEq.in[0] <== valueLength;
    isoLenEq.in[1] <== 10; // "YYYY-MM-DD"
    isIsoDateFormat * (1 - isoLenEq.out) === 0;

    component rocLenEq = IsEqual();
    rocLenEq.in[0] <== valueLength;
    rocLenEq.in[1] <== 7; // "YYYMMDD"
    isRocDateFormat * (1 - rocLenEq.out) === 0;

    // The ISO separators are not read by the date arithmetic, so pin them.
    isIsoDateFormat * (value[4] - 45) === 0; // '-'
    isIsoDateFormat * (value[7] - 45) === 0;

    // ISO reads 0-3, 5, 6, 8, 9; ROC reads 0-6. Index 7 is read by neither.
    var isoUsesDigit[10] = [1, 1, 1, 1, 0, 1, 1, 0, 1, 1];
    var rocUsesDigit[10] = [1, 1, 1, 1, 1, 1, 1, 0, 0, 0];

    component dateGe48[10];
    component dateLe57[10];
    signal dateDigitActive[10];
    for (var i = 0; i < 10; i++) {
        dateDigitActive[i] <== isIsoDateFormat * isoUsesDigit[i] + isRocDateFormat * rocUsesDigit[i];

        dateGe48[i] = GreaterEqThan(9);
        dateGe48[i].in[0] <== value[i];
        dateGe48[i].in[1] <== 48;

        dateLe57[i] = LessEqThan(9);
        dateLe57[i].in[0] <== value[i];
        dateLe57[i].in[1] <== 57;

        dateDigitActive[i] * (1 - dateGe48[i].out) === 0;
        dateDigitActive[i] * (1 - dateLe57[i].out) === 0;
    }

    // ===== Select based on format =====
    // Format 4: String — pack ASCII bytes big-endian into a single field element.
    // "TW" → 84*256 + 87 = 21591. For compatibility with VALUE_BITS=64 comparisons,
    // string values are constrained to <= 8 bytes.
    // Verifier supplies the same packed integer as compareValue; EvalPredicate uses op==.
    signal strAccum[valueLen + 1];
    strAccum[0] <== 0;

    component strLenLe8 = LessEqThan(log2Ceil(valueLen + 1));
    strLenLe8.in[0] <== valueLength;
    strLenLe8.in[1] <== 8;
    isStringFormat * (1 - strLenLe8.out) === 0;

    // Big-endian packing erases leading zero bytes, so "\0A" packs to the same
    // integer as "A" and "\0" packs to 0 like the empty string and an inactive
    // slot. Predicates compare the packed integer alone, so a leading NUL would
    // let one signed value satisfy a policy written for a different string.
    // A legitimate string claim never starts with NUL, so require the first
    // byte to be non-zero whenever the value is non-empty.
    component strHasBytes = GreaterThan(log2Ceil(valueLen + 1));
    strHasBytes.in[0] <== valueLength;
    strHasBytes.in[1] <== 0;

    component strFirstByteZero = IsZero();
    strFirstByteZero.in <== value[0];

    signal strLeadingNul <== strHasBytes.out * strFirstByteZero.out;
    isStringFormat * strLeadingNul === 0;

    // Scale by 256 only within valueLength; past the value the multiplier is 1
    // so trailing padding does not inflate the packed integer.
    component strLenGt[valueLen];
    signal strScaled[valueLen];
    for (var i = 0; i < valueLen; i++) {
        strLenGt[i] = GreaterThan(log2Ceil(valueLen + 1));
        strLenGt[i].in[0] <== valueLength;
        strLenGt[i].in[1] <== i;

        strScaled[i] <== strAccum[i] * (255 * strLenGt[i].out + 1);
        strAccum[i + 1] <== strScaled[i] + value[i] * strLenGt[i].out;
    }
    signal strValue <== strAccum[valueLen];

    signal normBool <== isBoolFormat    * boolValue;
    signal normUint <== isUintFormat    * uintValue;
    signal normIso  <== isIsoDateFormat * isoDateValue;
    signal normRoc  <== isRocDateFormat * rocDateValue;
    signal normStr  <== isStringFormat  * strValue;

    normalizedValue <== normBool + normUint + normIso + normRoc + normStr;
}

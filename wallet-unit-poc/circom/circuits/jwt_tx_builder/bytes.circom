pragma circom 2.1.6;

include "circomlib/circuits/comparators.circom";

/// @title FindRealMessageLength
/// @notice Finds the length of the real message in a padded array by locating the first occurrence of 128
/// @dev This template is specifically designed for Base64 encoded strings followed by SHA-256 padding.
///      It works because:
///      1. Base64 uses characters with ASCII values < 128
///      2. SHA-256 padding starts with 128 (10000000 in binary)
///      3. The first 128 encountered marks the end of the Base64 string and start of padding
/// @input in[maxLength] The padded message array
/// @input maxLength The maximum possible length of the padded message
/// @output realLength The length of the real message (before padding)
template FindRealMessageLength(maxLength) {
    signal input in[maxLength];
    signal output realLength;

    // Signal to track if we've found 128
    signal found[maxLength + 1];
    found[0] <== 0;

    // Signal to accumulate the length
    signal lengthAcc[maxLength + 1];
    lengthAcc[0] <== 0;

    signal is128[maxLength];

    // Iterate through the array
    for (var i = 0; i < maxLength; i++) {
        // Check if current element is 128
        is128[i] <== IsEqual()([in[i], 128]);

        // Update found signal
        found[i + 1] <== found[i] + is128[i] - found[i] * is128[i];

        // If 128 not found yet, increment length
        lengthAcc[i + 1] <== lengthAcc[i] + 1 - found[i + 1];
    }

    // The final accumulated length is our real message length
    realLength <== lengthAcc[maxLength];

    // Constraint to ensure 128 was really found
    found[maxLength] === 1;
}

/// @title CountCharOccurrences
/// @notice Counts the number of occurrences of a specified character in an array
/// @dev This template iterates through the input array and counts how many times the specified character appears.
/// @input in[maxLength] The input array in which to count occurrences of the character
/// @input char The character to count within the input array
/// @output count The number of times the specified character appears in the input array
template CountCharOccurrences(maxLength) {
    signal input in[maxLength];
    signal input char;
    signal output count;

    signal match[maxLength];
    signal counter[maxLength];

    match[0] <== IsEqual()([in[0], char]);
    counter[0] <== match[0];

    for (var i = 1; i < maxLength; i++) {
        match[i] <== IsEqual()([in[i], char]);
        counter[i] <== counter[i-1] + match[i];
    }

    count <== counter[maxLength-1];
}

/// @title CountPatternOccurrences
/// @notice Counts the positions i where in[i..i+patLen) equals the constant `pattern`
/// @dev Each window is packed little-endian into one field element and compared with
///      a single IsZero. The packing is injective only when every in[j] is already
///      constrained to a byte (e.g. Base64Decode output); callers must ensure that.
/// @param maxLength length of `in`
/// @param patLen number of bytes in `pattern`
/// @param pattern the bytes to look for
/// @input in[maxLength] byte array to search
/// @output count number of windows equal to `pattern`
template CountPatternOccurrences(maxLength, patLen, pattern) {
    assert(patLen * 8 < 252);
    assert(patLen <= maxLength);

    signal input in[maxLength];
    signal output count;

    var target = 0;
    for (var k = 0; k < patLen; k++) {
        target += pattern[k] * 256 ** k;
    }

    var n = maxLength - patLen + 1;
    signal match[n];
    var acc = 0;
    for (var i = 0; i < n; i++) {
        var packed = 0;
        for (var k = 0; k < patLen; k++) {
            packed += in[i + k] * 256 ** k;
        }
        match[i] <== IsZero()(packed - target);
        acc += match[i];
    }

    count <== acc;
}
pragma circom 2.1.6;
include "../jwt_tx_builder/array.circom";
include "@zk-email/circuits/lib/base64.circom";
include "@zk-email/circuits/lib/sha.circom";
include "../utils/utils.circom";

/// @title ClaimDecoder
/// @notice Decodes multiple Base64 input claims that might be padded with zeros
/// @param maxClaims: the maximum number of claims to process
/// @param maxClaimsLength: the maximum number of characters in each Base64 input array
/// @input claims: array of raw Base64 input arrays, each padded with zeros
/// @input claimLengths: array containing the actual length of each Base64 claim
/// @output decodedClaims: array of decoded outputs
template ClaimDecoder(maxMatches, maxClaimsLength) {
    var decodedLen = (maxClaimsLength * 3) / 4;

    signal input claims[maxMatches][maxClaimsLength];
    signal input claimLengths[maxMatches];
    signal input decodeFlags[maxMatches];

    signal output decodedClaims[maxMatches][decodedLen];

    component paddedClaims[maxMatches];
    signal paddedOrConst[maxMatches][maxClaimsLength];
    component claimDecoders[maxMatches];

    for (var i = 0; i < maxMatches; i++) {
        paddedClaims[i] = SelectSubArrayBase64(maxClaimsLength,maxClaimsLength);
        paddedClaims[i].in <== claims[i];
        paddedClaims[i].startIndex <== 0;
        paddedClaims[i].length <== claimLengths[i];

        for (var j = 0; j < maxClaimsLength; j++) {
            paddedOrConst[i][j] <== paddedClaims[i].out[j] * decodeFlags[i] + 65 * (1 - decodeFlags[i]);
        }

        claimDecoders[i] = Base64Decode(decodedLen);
        claimDecoders[i].in <== paddedOrConst[i];

        decodeFlags[i] * decodeFlags[i] === decodeFlags[i];

        for (var j = 0; j < decodedLen; j++) {
            decodedClaims[i][j] <== claimDecoders[i].out[j] * decodeFlags[i];
        }
    }
}   

template ClaimComparator(maxMatches , maxSubstringLength){
    signal input claimHashes[maxMatches][32]; // hashed claims from rawclaims
    signal input claimLengths[maxMatches];
    
    signal input matchSubstring[maxMatches][maxSubstringLength]; // hashed claims in base64url encoded
    signal input matchLength[maxMatches];

    component isZero[maxMatches];
    signal useClaim[maxMatches];
    for (var i = 0; i < maxMatches; i++) {
        isZero[i] = IsEqual();
        isZero[i].in[0] <== claimLengths[i];
        isZero[i].in[1] <== 0;
        useClaim[i] <== 1 - isZero[i].out;
        useClaim[i] * (1 - useClaim[i]) === 0;
    }

    // Only decode match entries that correspond to real claims; 
    // otherwise feed padded 'A's so DecodeSD never parses the helper patterns like "x":" or "y":".

    signal sanitizedSubstring[maxMatches][maxSubstringLength];
    signal effectiveLen[maxMatches];
    component sdDecoders[maxMatches];
    for (var i = 0; i < maxMatches; i++) {
        for (var j = 0; j < maxSubstringLength; j++) {
            sanitizedSubstring[i][j] <== matchSubstring[i][j] * useClaim[i] + 65 * (1 - useClaim[i]);
        }

        effectiveLen[i] <== matchLength[i] * useClaim[i];

        sdDecoders[i] = DecodeSD(maxSubstringLength, 32);
        sdDecoders[i].sdBytes <== sanitizedSubstring[i];
        sdDecoders[i].sdLen   <== effectiveLen[i];
    }

    component eq[maxMatches][32];
    for (var i = 0; i < maxMatches; i++) {
        for (var j = 0; j < 32; j++) {
            eq[i][j] = IsEqual();
            eq[i][j].in[0] <== claimHashes[i][j];
            eq[i][j].in[1] <== sdDecoders[i].base64Out[j];
            eq[i][j].out * useClaim[i] === useClaim[i];
        }
    }
}

// Bind the decoder's length to canonical SHA-256 padding for the same bytes.
template ClaimSha256Length(maxClaimsLength) {
    assert(maxClaimsLength == 128);

    signal input paddedIn[maxClaimsLength];
    signal input messageLength;
    signal output paddedLength;

    // A 128-byte SHA buffer holds at most 119 disclosure bytes.
    component lengthBits = Num2Bits(7);
    lengthBits.in <== messageLength;
    component lengthFits = LessThan(7);
    lengthFits.in[0] <== messageLength;
    lengthFits.in[1] <== 120;
    lengthFits.out === 1;

    component lengthIsZero = IsZero();
    lengthIsZero.in <== messageLength;
    signal isUsed <== 1 - lengthIsZero.out;

    component oneBlockCheck = LessThan(7);
    oneBlockCheck.in[0] <== messageLength;
    oneBlockCheck.in[1] <== 56;
    signal oneBlock <== oneBlockCheck.out;
    paddedLength <== 64 * oneBlock + 128 * (1 - oneBlock);

    signal activeOneBlock <== isUsed * oneBlock;
    signal activeTwoBlock <== isUsed * (1 - oneBlock);

    // afterMessage[j] is 1 exactly when j exceeds messageLength. Its single
    // transition identifies the 0x80 marker; later bytes must be zero.
    signal afterMessage[121];
    afterMessage[0] <== 0;
    afterMessage[120] <== 1;
    component beforeIndex[119];
    for (var j = 1; j < 120; j++) {
        beforeIndex[j - 1] = LessThan(7);
        beforeIndex[j - 1].in[0] <== messageLength;
        beforeIndex[j - 1].in[1] <== j;
        afterMessage[j] <== beforeIndex[j - 1].out;
    }

    signal paddingGate[120];
    signal expectedPaddingByte[120];
    for (var j = 0; j < 120; j++) {
        expectedPaddingByte[j] <== 128 * (afterMessage[j + 1] - afterMessage[j]);
        if (j < 56) {
            paddingGate[j] <== isUsed * afterMessage[j + 1];
        } else {
            paddingGate[j] <== activeTwoBlock * afterMessage[j + 1];
        }
        paddingGate[j] * (paddedIn[j] - expectedPaddingByte[j]) === 0;
    }

    // The message is < 120 bytes, so its bit length fits in two bytes.
    // The six leading bytes of the SHA trailer must be zero.
    for (var j = 56; j < 62; j++) activeOneBlock * paddedIn[j] === 0;
    activeOneBlock * (paddedIn[62] * 256 + paddedIn[63] - messageLength * 8) === 0;
    for (var j = 120; j < 126; j++) activeTwoBlock * paddedIn[j] === 0;
    activeTwoBlock * (paddedIn[126] * 256 + paddedIn[127] - messageLength * 8) === 0;
}

template ClaimHasher(maxMatches, maxClaimsLength){
    signal input claims[maxMatches][maxClaimsLength];
    signal input claimLengths[maxMatches];

    component claimHasher[maxMatches];
    component claimPadding[maxMatches];
    component hashByteConvert[maxMatches][32];
    signal output claimHashes[maxMatches][32]; 

    for (var i = 0; i < maxMatches; i++) {
        claimPadding[i] = ClaimSha256Length(maxClaimsLength);
        claimPadding[i].paddedIn <== claims[i];
        claimPadding[i].messageLength <== claimLengths[i];

        claimHasher[i] = Sha256Bytes(maxClaimsLength);
        claimHasher[i].paddedIn <== claims[i];
        claimHasher[i].paddedInLength <== claimPadding[i].paddedLength;

         for (var j = 0; j < 32; j++) {
            hashByteConvert[i][j] = Bits2Num(8);
            for (var k = 0; k < 8; k++) {
                    hashByteConvert[i][j].in[7-k] <== claimHasher[i].out[j * 8 + k];
                 }
        claimHashes[i][j] <== hashByteConvert[i][j].out;
        }
    }
}

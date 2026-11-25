pragma circom 2.2.3;

include "../jwt_tx_builder/bytes.circom";
include "@zk-email/circuits/utils/array.circom";
include "circomlib/circuits/comparators.circom";

// Find a unique named object member in the supplied parent scope. The key is
// matched at a member boundary. Whitespace may surround the colon.
template DeviceKeyObject(n, keyLength, key, objectDepth) {
    signal input payload[n];
    signal input memberStart[n];
    signal input space[n];
    signal input colon[n];
    signal input openBrace[n];
    signal input closeBrace[n];
    signal input depth[n + 1];
    signal input parent[n];
    signal output inside[n + 1];

    signal matches[n - keyLength + 1] <== PatternMatches(n, keyLength, key)(payload);
    signal member[n - keyLength + 1];
    signal start[n - keyLength + 1];
    for (var i = 0; i <= n - keyLength; i++) {
        member[i] <== matches[i] * memberStart[i];
        start[i] <== member[i] * parent[i];
    }

    signal afterKey[n + 1];
    signal afterColon[n + 1];
    afterKey[0] <== 0;
    afterColon[0] <== 0;
    inside[0] <== 0;
    signal colonAfterKey[n];
    signal opens[n];
    signal atDepth[n];
    signal closes[n];

    var memberCount = 0;
    var objectCount = 0;
    for (var i = 0; i < n; i++) {
        var keyEnds = i >= keyLength - 1 ? start[i - keyLength + 1] : 0;
        afterKey[i + 1] <== keyEnds + afterKey[i] * space[i];
        colonAfterKey[i] <== afterKey[i] * colon[i];
        afterColon[i + 1] <== colonAfterKey[i] + afterColon[i] * space[i];

        opens[i] <== afterColon[i] * openBrace[i];
        atDepth[i] <== IsEqual()([depth[i], objectDepth]);
        closes[i] <== atDepth[i] * closeBrace[i];
        inside[i + 1] <== opens[i] + inside[i] * (1 - closes[i]);
        memberCount += keyEnds;
        objectCount += opens[i];
    }
    memberCount === 1;
    objectCount === 1;
    inside[n] === 0;
}

// Check the path in the signed JSON. Count both object and array delimiters
// outside strings to distinguish direct members. The input must contain bytes
// from a JSON payload, and JWT separately checks the coordinate value prefixes.
template BindDeviceKeyPath(n) {
    signal input payload[n];
    signal input xIndex;
    signal input yIndex;

    signal inString[n + 1];
    signal escaped[n + 1];
    signal separator[n + 1];
    signal depth[n + 1];
    signal memberStart[n];
    signal space[n];
    signal colon[n];
    signal openBrace[n];
    signal closeBrace[n];
    signal rootScope[n];
    signal cnfDepth[n];
    signal jwkDepth[n];
    signal inMemberName[n + 1];
    inString[0] <== 0;
    escaped[0] <== 0;
    separator[0] <== 0;
    depth[0] <== 0;
    inMemberName[0] <== 0;

    signal quote[n];
    signal backslash[n];
    signal structuralQuote[n];
    signal opensString[n];
    signal tab[n];
    signal lf[n];
    signal cr[n];
    signal blank[n];
    signal braceOpenByte[n];
    signal braceCloseByte[n];
    signal arrayOpenByte[n];
    signal arrayCloseByte[n];
    signal comma[n];
    signal colonByte[n];
    signal openArray[n];
    signal closeArray[n];
    signal atRoot[n];
    signal zero[n];
    signal rootOpen[n];
    signal memberBoundary[n];
    signal jwkScope[n];
    signal xMember[n];
    signal yMember[n];
    signal escapedMember[n];

    var roots = 0;
    for (var i = 0; i < n; i++) {
        quote[i] <== IsEqual()([payload[i], 34]);
        backslash[i] <== IsEqual()([payload[i], 92]);
        structuralQuote[i] <== quote[i] * (1 - escaped[i]);
        opensString[i] <== structuralQuote[i] * (1 - inString[i]);
        inString[i + 1] <== inString[i] + 2 * opensString[i] - structuralQuote[i];
        escaped[i + 1] <== backslash[i] * (inString[i] - escaped[i]);
        memberStart[i] <== opensString[i] * separator[i];
        inMemberName[i + 1] <== memberStart[i] + inMemberName[i] * (1 - structuralQuote[i]);

        tab[i] <== IsEqual()([payload[i], 9]);
        lf[i] <== IsEqual()([payload[i], 10]);
        cr[i] <== IsEqual()([payload[i], 13]);
        blank[i] <== IsEqual()([payload[i], 32]);
        space[i] <== (tab[i] + lf[i] + cr[i] + blank[i]) * (1 - inString[i]);

        braceOpenByte[i] <== IsEqual()([payload[i], 123]);
        braceCloseByte[i] <== IsEqual()([payload[i], 125]);
        arrayOpenByte[i] <== IsEqual()([payload[i], 91]);
        arrayCloseByte[i] <== IsEqual()([payload[i], 93]);
        comma[i] <== IsEqual()([payload[i], 44]);
        colonByte[i] <== IsEqual()([payload[i], 58]);
        openBrace[i] <== braceOpenByte[i] * (1 - inString[i]);
        closeBrace[i] <== braceCloseByte[i] * (1 - inString[i]);
        colon[i] <== colonByte[i] * (1 - inString[i]);

        openArray[i] <== arrayOpenByte[i] * (1 - inString[i]);
        closeArray[i] <== arrayCloseByte[i] * (1 - inString[i]);
        depth[i + 1] <== depth[i] + openBrace[i] + openArray[i] - closeBrace[i] - closeArray[i];
        atRoot[i] <== IsZero()(depth[i]);
        zero[i] <== IsZero()(payload[i]);
        atRoot[i] * (1 - openBrace[i] - space[i] - zero[i]) === 0;
        rootOpen[i] <== atRoot[i] * openBrace[i];
        roots += rootOpen[i];

        memberBoundary[i] <== (braceOpenByte[i] + comma[i]) * (1 - inString[i]);
        separator[i + 1] <== memberBoundary[i] + separator[i] * space[i];
        rootScope[i] <== IsEqual()([depth[i], 1]);
        cnfDepth[i] <== IsEqual()([depth[i], 2]);
        jwkDepth[i] <== IsEqual()([depth[i], 3]);
    }
    roots === 1;
    depth[n] === 0;
    inString[n] === 0;

    signal inCnf[n + 1] <== DeviceKeyObject(n, 5, [34, 99, 110, 102, 34], 2)(
        payload, memberStart, space, colon, openBrace, closeBrace, depth, rootScope
    );
    signal cnfScope[n];
    for (var i = 0; i < n; i++) {
        cnfScope[i] <== inCnf[i] * cnfDepth[i];
    }
    signal inJwk[n + 1] <== DeviceKeyObject(n, 5, [34, 106, 119, 107, 34], 3)(
        payload, memberStart, space, colon, openBrace, closeBrace, depth, cnfScope
    );

    signal xName[n - 2] <== PatternMatches(n, 3, [34, 120, 34])(payload);
    signal yName[n - 2] <== PatternMatches(n, 3, [34, 121, 34])(payload);
    signal keyStart[n];
    var xCount = 0;
    var yCount = 0;
    for (var i = 0; i < n; i++) {
        jwkScope[i] <== inJwk[i] * jwkDepth[i];
        keyStart[i] <== memberStart[i] * jwkScope[i];
        if (i <= n - 3) {
            xMember[i] <== keyStart[i] * xName[i];
            yMember[i] <== keyStart[i] * yName[i];
        } else {
            xMember[i] <== 0;
            yMember[i] <== 0;
        }
        xCount += xMember[i];
        yCount += yMember[i];

        // Require literal names in the objects used for path resolution so an
        // escaped spelling cannot introduce a second name that JSON would decode identically.
        escapedMember[i] <== inMemberName[i] * backslash[i];
        escapedMember[i] * (rootScope[i] + cnfScope[i] + jwkScope[i]) === 0;
    }
    xCount === 1;
    yCount === 1;
    signal xAtMember <== ItemAtIndex(n)(xMember, xIndex);
    signal yAtMember <== ItemAtIndex(n)(yMember, yIndex);
    xAtMember === 1;
    yAtMember === 1;

    // The pinned anchors end with an opening quote. Each coordinate is a
    // 43-character base64url encoding and must end at the closing quote.
    signal xEnd <== ItemAtIndex(n)(payload, xIndex + 5 + 43);
    signal yEnd <== ItemAtIndex(n)(payload, yIndex + 5 + 43);
    xEnd === 34;
    yEnd === 34;
}

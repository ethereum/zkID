pragma circom 2.2.3;

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

/// @title BitsBelowFieldModulus
/// @notice Constrains little-endian bits `in` to encode an integer below the field
///         modulus p, the P-256 base prime (secq256r1).
/// @notice p = 2^256 - 2^224 + 2^192 + 2^96 - 1, so its bit i is 1 exactly for
///         i < 96, i = 192 and i >= 224.
/// @notice Scans from the top bit. `eq[i]` is 1 while bits 255..i equal p's; the
///         integer is below p when some bit is 0 where p has 1 under an equal prefix.
template BitsBelowFieldModulus() {
    signal input in[256];

    signal eq[256];
    var lt = 0;
    for (var i = 255; i >= 0; i--) {
        var pBit = (i < 96 || i == 192 || i >= 224) ? 1 : 0;
        if (pBit == 1) {
            if (i == 255) {
                eq[i] <== in[i];
                lt += 1 - eq[i];
            } else {
                eq[i] <== eq[i + 1] * in[i];
                // eq[i + 1] * (1 - in[i]): the prefix was equal and this bit is below p's.
                lt += eq[i + 1] - eq[i];
            }
        } else {
            // p's bit is 0 here, so a 1 under an equal prefix exceeds p and lt stays 0.
            eq[i] <== eq[i + 1] * (1 - in[i]);
        }
    }
    // At most one term of lt is 1, since eq never returns to 1 once it drops.
    lt === 1;
}

/// @title IssuerKeyBits
/// @notice The issuer key as big-endian be32(x) || be32(y).
/// @notice The bits encode x and y below p, so each key has exactly one encoding and
///         every hash over these bits has one value per key.
template IssuerKeyBits() {
    signal input pubKeyX;
    signal input pubKeyY;
    signal output out[512];

    component xBits = AnchoredNum2Bits(256);
    xBits.in <== pubKeyX;
    component xCanonical = BitsBelowFieldModulus();
    xCanonical.in <== xBits.out;
    component yBits = AnchoredNum2Bits(256);
    yBits.in <== pubKeyY;
    component yCanonical = BitsBelowFieldModulus();
    yCanonical.in <== yBits.out;

    for (var i = 0; i < 256; i++) {
        out[i] <== xBits.out[255 - i];
        out[256 + i] <== yBits.out[255 - i];
    }
}

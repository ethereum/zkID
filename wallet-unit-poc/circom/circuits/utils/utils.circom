pragma circom 2.2.3;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/multiplexer.circom";
include "circomlib/circuits/poseidon.circom";
include "@zk-email/circuits/utils/array.circom";


/// @title AssertSliceInTBS
/// @notice Proves that the byte slice [offset, offset+length) lies entirely
///         within a MOICA-signed TBS region of tbsLen bytes.
///         Also range-checks offset and length to 13 bits each, preventing
///         field-element wrap-around on the LessEqThan comparator (which
///         assumes both operands fit in 14 bits after being summed).
///         Caller must separately ensure tbsLen < 2^13 (one Num2Bits(13) call).
template AssertSliceInTBS() {
    signal input offset;
    signal input length;
    signal input tbsLen;

    component offRng = Num2Bits(13);
    offRng.in <== offset;

    component lenRng = Num2Bits(13);
    lenRng.in <== length;

    // offset + length <= tbsLen
    // Both summands < 2^13, so their sum < 2^14 — safe for LessEqThan(14).
    component bnd = LessEqThan(14);
    bnd.in[0] <== offset + length;
    bnd.in[1] <== tbsLen;
    bnd.out === 1;
}

/// Extracts cert[subject_dn_offset .. +length] and asserts it equals subject_dn.
template VerifySubjectDN(MAX_CERT_LEN, MAX_SUBJECT_LEN) {
    signal input cert[MAX_CERT_LEN];
    signal input subject_dn[MAX_SUBJECT_LEN];
    signal input subject_dn_offset;
    signal input length;

    component extracted = SelectSubArray(MAX_CERT_LEN, MAX_SUBJECT_LEN);
    extracted.in <== cert;
    extracted.startIndex <== subject_dn_offset;
    extracted.length <== length;

    for (var i = 0; i < MAX_SUBJECT_LEN; i++) {
        extracted.out[i] === subject_dn[i];
    }
}

/// Validates ASN.1 INTEGER tag+length, extracts serial bytes, and reconstructs
/// a big-endian integer to assert it equals `target`.
///
/// `OFFSET` is the position of the first serial value byte. It is a template
/// parameter because the caller pins the bytes before the serial, so the
/// position is known at compile time; the tag and length bytes are read
/// directly instead of through a selector.
template VerifySerialNumber(MAX_CERT_LEN, MAX_SERIAL_LEN, OFFSET) {
    assert(OFFSET >= 2);
    assert(OFFSET + MAX_SERIAL_LEN <= MAX_CERT_LEN);

    signal input cert[MAX_CERT_LEN];
    signal input target;  // single big-endian integer

    // -----------------------------------------------------------------------
    // Step 0: Tag byte at (OFFSET-2) and length byte at (OFFSET-1)
    // -----------------------------------------------------------------------
    // Enforce ASN.1 INTEGER tag == 0x02
    cert[OFFSET - 2] === 2;

    signal actual_len;
    actual_len <== cert[OFFSET - 1];

    component lenGtZero = GreaterThan(8);
    lenGtZero.in[0] <== actual_len;
    lenGtZero.in[1] <== 0;
    lenGtZero.out === 1;

    component lenInRange = LessEqThan(8);
    lenInRange.in[0] <== actual_len;
    lenInRange.in[1] <== MAX_SERIAL_LEN;
    lenInRange.out === 1;

    // -----------------------------------------------------------------------
    // Step 1: Extract serial bytes using SelectSubArray (log-depth shift)
    // -----------------------------------------------------------------------
    component serialSel = SelectSubArray(MAX_CERT_LEN, MAX_SERIAL_LEN);
    serialSel.in <== cert;
    serialSel.startIndex <== OFFSET;
    serialSel.length <== actual_len;

    // -----------------------------------------------------------------------
    // Step 2: Reconstruct big-endian integer using actual_len-relative powers
    // -----------------------------------------------------------------------

    var pow256[MAX_SERIAL_LEN + 1];
    pow256[0] = 1;
    for (var k = 1; k <= MAX_SERIAL_LEN; k++) {
        pow256[k] = pow256[k-1] * 256;
    }

    component powEq[MAX_SERIAL_LEN][MAX_SERIAL_LEN + 1];
    signal powSelected[MAX_SERIAL_LEN][MAX_SERIAL_LEN + 1];
    signal powSum[MAX_SERIAL_LEN][MAX_SERIAL_LEN + 2];
    signal byte_weight[MAX_SERIAL_LEN];

    for (var i = 0; i < MAX_SERIAL_LEN; i++) {
        powSum[i][0] <== 0;
        for (var k = 0; k <= MAX_SERIAL_LEN; k++) {
            powEq[i][k] = IsEqual();
            powEq[i][k].in[0] <== actual_len;
            powEq[i][k].in[1] <== k + 1 + i;
            powSelected[i][k] <== pow256[k] * powEq[i][k].out;
            powSum[i][k+1] <== powSum[i][k] + powSelected[i][k];
        }
        byte_weight[i] <== powSum[i][MAX_SERIAL_LEN + 1];
    }

    signal weighted[MAX_SERIAL_LEN];
    for (var i = 0; i < MAX_SERIAL_LEN; i++) {
        weighted[i] <== serialSel.out[i] * byte_weight[i];
    }

    signal reconSum[MAX_SERIAL_LEN + 1];
    reconSum[0] <== 0;
    for (var i = 0; i < MAX_SERIAL_LEN; i++) {
        reconSum[i+1] <== reconSum[i] + weighted[i];
    }

    reconSum[MAX_SERIAL_LEN] === target;
}

/// @title ExtractModulus
/// @notice Extracts an RSA public key modulus from a DER-encoded certificate
/// @dev    SubjectPublicKeyInfo layout:
///           SEQUENCE {
///             SEQUENCE { OID rsaEncryption  NULL }
///             BIT STRING {
///               SEQUENCE {
///                 INTEGER  ← modulus value bytes start at modulusOffset
///                 INTEGER  ← exponent (65537)
///               }
///             }
///           }
///         Prover supplies modulusTagOffset pointing to the 0x02 INTEGER tag
///         and modulusOffset pointing to the first actual modulus byte
///         (after tag + length field + optional 0x00 sign byte).
///         Circuit validates the INTEGER tag at modulusTagOffset.
///         DER is big-endian; limbs are packed LSB-first for RSAVerifier65537.
///         For non-byte-aligned limb sizes (e.g. n=121), bits beyond
///         modulusBits in the top limb are zero-padded.
/// @param maxLen        Maximum certificate DER byte length
/// @param n             Bits per RSA limb (e.g. 121)
/// @param k             Number of RSA limbs (e.g. 17 for RSA-2048)
/// @param modulusBits   Actual RSA key size in bits (e.g. 2048) — must be
///                      divisible by 8. Separate from n*k (e.g. 121*17=2057).
/// @input in                Certificate DER bytes, zero-padded to maxLen
/// @input modulusOffset     Byte offset of first modulus value byte in `in`
///                          (points past tag + length field + sign byte)
/// @input modulusTagOffset  Byte offset of the INTEGER tag (0x02) in `in`
///                          Circuit asserts in[modulusTagOffset] == 2
/// @output out              Modulus as k limbs of n bits, LSB limb first
///                          Compatible with RSAVerifier65537(n, k)
template ExtractModulus(maxLen, n, k, modulusBits) {
    var modulusBytes = modulusBits \ 8;  // 2048\8 = 256 bytes

    signal input in[maxLen];
    signal input modulusOffset;
    signal input modulusTagOffset;
    signal output out[k];

    // ── Step 1: Validate INTEGER tag (0x02) at modulusTagOffset ──────────
    // Prevents prover from pointing at arbitrary bytes as the modulus
    component tagSel = Multiplexer(1, maxLen);
    for (var i = 0; i < maxLen; i++) {
        tagSel.inp[i][0] <== in[i];
    }
    tagSel.sel <== modulusTagOffset;
    tagSel.out[0] === 2;  // 0x02 = INTEGER tag

    // ── Step 2: Extract modulusBytes bytes starting at modulusOffset ──────
    // Uses clamped selector to avoid Multiplexer out-of-bounds assert
    component bytesel[modulusBytes];
    component ltn[modulusBytes];
    signal modBytes[modulusBytes];

    for (var i = 0; i < modulusBytes; i++) {
        // Check modulusOffset + i is within maxLen
        ltn[i] = LessThan(12);
        ltn[i].in[0] <== modulusOffset + i;
        ltn[i].in[1] <== maxLen;

        bytesel[i] = Multiplexer(1, maxLen);
        for (var j = 0; j < maxLen; j++) {
            bytesel[i].inp[j][0] <== in[j];
        }
        // Clamp selector: use modulusOffset+i if in bounds, else 0
        bytesel[i].sel <== ltn[i].out * (modulusOffset + i) +
                           (1 - ltn[i].out) * 0;

        // Zero out if out of bounds
        modBytes[i] <== bytesel[i].out[0] * ltn[i].out;
    }

    // ── Step 3: Bytes → flat bit array (MSB first) ────────────────────────
    // modBytes[0] is the most significant byte (big-endian DER)
    // bits[0] = MSB of modBytes[0], bits[modulusBits-1] = LSB of last byte
    component byte2bits[modulusBytes];
    signal bits[modulusBytes * 8];  // = modulusBits bits

    for (var i = 0; i < modulusBytes; i++) {
        byte2bits[i] = Num2Bits(8);
        byte2bits[i].in <== modBytes[i];
        for (var j = 0; j < 8; j++) {
            bits[i * 8 + j] <== byte2bits[i].out[7 - j];  // MSB first
        }
    }

    // ── Step 4: Pack bits → k limbs of n bits, LSB limb first ────────────
    // bits[0]          = MSB of modulus
    // bits[modulusBits-1] = LSB of modulus
    //
    // limb[0] = least significant n bits of modulus
    // limb[k-1] = most significant n bits of modulus
    //
    // For i-th limb, j-th bit:
    //   bitPos = i*n + j  (position from LSB end)
    //   maps to bits[modulusBits - 1 - bitPos]
    //
    // If bitPos >= modulusBits (top limb overflow when n*k > modulusBits),
    //   zero-pad those bits
    component b2n[k];

    for (var i = 0; i < k; i++) {
        b2n[i] = Bits2Num(n);
        for (var j = 0; j < n; j++) {
            var bitPos = i * n + j;
            if (bitPos < modulusBits) {
                b2n[i].in[j] <== bits[modulusBits - 1 - bitPos];
            } else {
                // Zero-pad top limb bits that exceed modulusBits
                // e.g. n=121, k=17: n*k=2057 but modulusBits=2048
                // limb[16] bits 2048..2056 are zero
                b2n[i].in[j] <== 0;
            }
        }
        out[i] <== b2n[i].out;
    }
}

template PackBytes(N_BYTES, TBS_LENGTH) {
    // packs N_BYTES into ceil(N_BYTES/31) field elements
    var BYTES_PER_FIELD = 31;
    var N_FIELDS = (N_BYTES + BYTES_PER_FIELD - 1) \ BYTES_PER_FIELD;

    signal input in[TBS_LENGTH];
    signal output out[N_FIELDS];

    for (var f = 0; f < N_FIELDS; f++) {
        var acc = 0;
        var shift = 1;
        for (var i = 0; i < BYTES_PER_FIELD; i++) {
            var idx = f * BYTES_PER_FIELD + i;
            if (idx < N_BYTES) {
                acc = acc + in[idx] * shift;
            }
            shift = shift * 256;
        }
        out[f] <== acc;
    }
}

template PoseidonBytes(N_BYTES) {
    var BYTES_PER_FIELD = 31;
    var N_FIELDS = (N_BYTES + BYTES_PER_FIELD - 1) \ BYTES_PER_FIELD;

    signal input in[N_BYTES];
    signal output out;

    // step 1: pack bytes → field elements
    component packer = PackBytes(N_BYTES, N_BYTES);
    for (var i = 0; i < N_BYTES; i++) {
        packer.in[i] <== in[i];
    }

    // step 2: hash packed field elements
    component hasher = Poseidon(N_FIELDS);
    for (var f = 0; f < N_FIELDS; f++) {
        hasher.inputs[f] <== packer.out[f];
    }

    out <== hasher.out;
}

/// Like PoseidonBytes but appends one extra field element before hashing.
/// Used to bind a byte array to an application-specific domain value.
template PoseidonBytesWithField(N_BYTES) {
    var BYTES_PER_FIELD = 31;
    var N_FIELDS = (N_BYTES + BYTES_PER_FIELD - 1) \ BYTES_PER_FIELD;

    signal input in[N_BYTES];
    signal input extra;
    signal output out;

    component packer = PackBytes(N_BYTES, N_BYTES);
    for (var i = 0; i < N_BYTES; i++) {
        packer.in[i] <== in[i];
    }

    component hasher = Poseidon(N_FIELDS + 1);
    for (var f = 0; f < N_FIELDS; f++) {
        hasher.inputs[f] <== packer.out[f];
    }
    hasher.inputs[N_FIELDS] <== extra;

    out <== hasher.out;
}

/// @title VerifyValidity
/// @notice Walks the head of a v3 TBSCertificate to the Validity field and
///         asserts notBefore <= currentTime <= notAfter.
///         Layout walked (all offsets derived, none prover-supplied):
///           [0..4)   outer SEQUENCE header (30 82 hh ll)   - pinned by caller
///           [4..9)   version a0 03 02 01 02                 - pinned by caller
///           [9]      serial INTEGER tag, [10] serial length - checked by VerifySerialNumber
///           p1 = 11 + serialLen:      AlgorithmIdentifier sha256WithRSAEncryption (15 bytes)
///           p1 + 15:                  issuer Name SEQUENCE, short-form length
///           p3 = p1 + 17 + issuerLen: Validity = 30 1e 17 0d <12 digits> 5a 17 0d <12 digits> 5a
///         Only UTCTime is accepted; GeneralizedTime (notAfter >= 2050) fails.
///         Caller must ensure tbs[i] are bytes (done by the SHA-256 gadget).
/// @param MAX_SERIAL_LEN  Max serial length in bytes (<= 20)
/// @input tbs          First 256 bytes of the TBS
/// @input currentTime  Decimal integer YYMMDDHHMMSS (UTC)
/// @output subjectOffset  Offset of the subject Name, the field after Validity (<= 207)
/// @output subjectHeader  The 3 bytes at subjectOffset (tag + up to 2 length bytes)
template VerifyValidity(MAX_SERIAL_LEN) {
    signal input tbs[256];
    signal input currentTime;
    signal output subjectOffset;
    signal output subjectHeader[3];

    assert(MAX_SERIAL_LEN <= 20);

    // Serial length byte. Re-checked here so the bound on p1 does not depend
    // on the caller.
    signal serialLen <== tbs[10];
    component serialLenOk = LessEqThan(8);
    serialLenOk.in[0] <== serialLen;
    serialLenOk.in[1] <== MAX_SERIAL_LEN;
    serialLenOk.out === 1;

    // p1 in [11, 31]; p1 + 17 <= 48 < 64.
    signal p1 <== 11 + serialLen;
    component head = VarShiftLeft(64, 17);
    for (var i = 0; i < 64; i++) {
        head.in[i] <== tbs[i];
    }
    head.shift <== p1;

    // AlgorithmIdentifier { sha256WithRSAEncryption, NULL }
    var sigAlg[15] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                      0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00];
    for (var i = 0; i < 15; i++) {
        head.out[i] === sigAlg[i];
    }

    // Issuer Name: SEQUENCE with short-form length (< 128).
    head.out[15] === 0x30;
    signal issuerLen <== head.out[16];
    component issuerLenShort = Num2Bits(7);
    issuerLenShort.in <== issuerLen;

    // p3 <= 31 + 17 + 127 = 175. Read the 32 bytes of Validity plus the
    // 3-byte header of the field that follows it; p3 + 35 <= 210 < 256.
    signal p3 <== p1 + 17 + issuerLen;
    component val = VarShiftLeft(256, 35);
    for (var i = 0; i < 256; i++) {
        val.in[i] <== tbs[i];
    }
    val.shift <== p3;

    // Validity ::= SEQUENCE { notBefore UTCTime, notAfter UTCTime }
    val.out[0] === 0x30;
    val.out[1] === 0x1e;
    val.out[2] === 0x17;
    val.out[3] === 0x0d;
    val.out[16] === 0x5a;
    val.out[17] === 0x17;
    val.out[18] === 0x0d;
    val.out[31] === 0x5a;

    // 12 ASCII digits each -> decimal integer YYMMDDHHMMSS.
    signal nbDigit[12];
    signal naDigit[12];
    component nbBits[12];
    component naBits[12];
    component nbLt[12];
    component naLt[12];
    var nbAcc = 0;
    var naAcc = 0;
    for (var i = 0; i < 12; i++) {
        nbDigit[i] <== val.out[4 + i] - 48;
        naDigit[i] <== val.out[19 + i] - 48;

        nbBits[i] = Num2Bits(4);
        nbBits[i].in <== nbDigit[i];
        nbLt[i] = LessThan(4);
        nbLt[i].in[0] <== nbDigit[i];
        nbLt[i].in[1] <== 10;
        nbLt[i].out === 1;

        naBits[i] = Num2Bits(4);
        naBits[i].in <== naDigit[i];
        naLt[i] = LessThan(4);
        naLt[i].in[0] <== naDigit[i];
        naLt[i].in[1] <== 10;
        naLt[i].out === 1;

        nbAcc = nbAcc * 10 + nbDigit[i];
        naAcc = naAcc * 10 + naDigit[i];
    }
    signal notBefore <== nbAcc;
    signal notAfter <== naAcc;

    // Both date integers are < 10^12 < 2^40. Range-check currentTime so the
    // comparators' precondition holds.
    component ctBits = Num2Bits(40);
    ctBits.in <== currentTime;

    component afterStart = LessEqThan(40);
    afterStart.in[0] <== notBefore;
    afterStart.in[1] <== currentTime;
    afterStart.out === 1;

    component beforeEnd = LessEqThan(40);
    beforeEnd.in[0] <== currentTime;
    beforeEnd.in[1] <== notAfter;
    beforeEnd.out === 1;

    subjectOffset <== p3 + 32;
    for (var i = 0; i < 3; i++) {
        subjectHeader[i] <== val.out[32 + i];
    }
}

/// @title LocateModulus
/// @notice Derives the offset of the subject public key's modulus INTEGER tag
///         from the DER structure, continuing the walk VerifyValidity started:
///           subjectOffset:  subject Name SEQUENCE, length in short form
///                           (< 128) or one-byte long form 0x81 LL (128..255)
///           q = end of Name: SubjectPublicKeyInfo for a 2048-bit RSA key,
///                            whose 28 bytes up to the modulus are fixed
///           q + 28:          modulus INTEGER tag
///         Subject Names longer than 255 bytes and keys other than RSA-2048
///         are rejected.
///         Caller must ensure tbs[i] are bytes (done by the SHA-256 gadget).
/// @input tbs            First 512 bytes of the TBS
/// @input subjectOffset  From VerifyValidity (<= 207)
/// @input subjectHeader  From VerifyValidity
/// @output modulusTagOffset  Offset of the modulus INTEGER tag (<= 493)
template LocateModulus() {
    signal input tbs[512];
    signal input subjectOffset;
    signal input subjectHeader[3];
    signal output modulusTagOffset;

    subjectHeader[0] === 0x30;
    component b1Bits = Num2Bits(8);
    b1Bits.in <== subjectHeader[1];
    component b2Bits = Num2Bits(8);
    b2Bits.in <== subjectHeader[2];

    component isLong = IsEqual();
    isLong.in[0] <== subjectHeader[1];
    isLong.in[1] <== 0x81;
    // The first length byte has its high bit set iff the form is 0x81, so
    // 0x80 and 0x82..0xff are rejected.
    b1Bits.out[7] === isLong.out;
    // DER minimal encoding: the 0x81 form carries a length >= 128.
    isLong.out * (1 - b2Bits.out[7]) === 0;

    signal subjectLen <== isLong.out * (subjectHeader[2] - subjectHeader[1]) + subjectHeader[1];

    // q <= 207 + 3 + 255 = 465; q + 28 <= 493 < 512.
    signal q <== subjectOffset + 2 + isLong.out + subjectLen;
    component spki = VarShiftLeft(512, 28);
    for (var i = 0; i < 512; i++) {
        spki.in[i] <== tbs[i];
    }
    spki.shift <== q;

    //   30 82 01 22                                    SubjectPublicKeyInfo (290)
    //   30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00   rsaEncryption, NULL
    //   03 82 01 0f 00                                 BIT STRING (271), 0 unused bits
    //   30 82 01 0a                                    RSAPublicKey (266)
    var spkiHead[28] = [0x30, 0x82, 0x01, 0x22,
                        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
                        0x03, 0x82, 0x01, 0x0f, 0x00,
                        0x30, 0x82, 0x01, 0x0a];
    for (var i = 0; i < 28; i++) {
        spki.out[i] === spkiHead[i];
    }

    modulusTagOffset <== q + 28;
}

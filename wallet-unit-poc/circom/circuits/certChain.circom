pragma circom 2.2.3;

include "rs256.circom";
include "components/pkCommit.circom";

/// @title CertChainRSA256
/// @notice Circuit A of the CertChain + UserSig pair. Proves: "I hold a
///         non-revoked, MOICA-issued cert whose RSA public key hashes (with
///         pkBlind) to pkCommit." Issuer RSA params are separate from user
///         params so MOICA-G3's 4096-bit CA can certify a 2048-bit user key.
///         pkCommit is computed over kUser limbs so it byte-matches
///         UserSigRSA256's; the verifier checks `pk_commit_A == pk_commit_B`
///         to prevent proof-mixing.
///
/// @param maxMessageLength    Max TBS / cert byte length (1536)
/// @param n                   RSA limb bits (e.g. 121)
/// @param kIssuer            Issuer RSA limb count (17 for G2, 34 for G3)
/// @param modulusBitsIssuer   Issuer RSA key bits (2048 for G2, 4096 for G3)
/// @param kUser              User RSA limb count (always 17 — MOICA user keys are 2048-bit)
/// @param modulusBitsUser     User RSA key bits (always 2048)
/// @param smtDepth            SMT non-membership proof depth (e.g. 128)
/// @param maxSerialNumberLength  Max cert serial bytes (e.g. 16)
template CertChainRSA256(
    maxMessageLength,
    n,
    kIssuer,
    modulusBitsIssuer,
    kUser,
    modulusBitsUser,
    smtDepth,
    maxSerialNumberLength
) {
    // === Issuer (cert chain) — sized to kIssuer ===
    signal input issuerTbs[maxMessageLength];
    signal input issuerTbsLength;
    signal input actualIssuerTbsLength;
    signal input issuerRsaModulus[kIssuer];
    signal input issuerRsaSignature[kIssuer];

    // === Revocation (SMT non-membership) ===
    signal input smtRoot;
    signal input serialNumber;
    signal input smtSiblings[smtDepth];
    signal input smtOldKey;
    signal input smtOldValue;
    signal input smtIsOld0;

    // === Validity ===
    // Verifier-supplied time as the decimal integer YYMMDDHHMMSS (UTC).
    signal input currentTime;

    // === Linking (private; same value used in UserSigRSA256) ===
    signal input pkBlind;

    // === Outputs ===
    signal output pkCommit;

    // AssertSliceInTBS needs actualIssuerTbsLength fit in 13 bits.
    component tlRange = Num2Bits(13);
    tlRange.in <== actualIssuerTbsLength;

    // issuerTbsLength is the SHA-256-padded length, actualIssuerTbsLength the
    // raw DER length. SHA-256 padding adds 9..72 bytes; 128 is a safe upper
    // bound: actual <= padded <= actual + 128.
    component tbsLenLB = LessEqThan(13);
    tbsLenLB.in[0] <== actualIssuerTbsLength;
    tbsLenLB.in[1] <== issuerTbsLength;
    tbsLenLB.out === 1;

    component tbsLenUB = LessEqThan(14);
    tbsLenUB.in[0] <== issuerTbsLength;
    tbsLenUB.in[1] <== actualIssuerTbsLength + 128;
    tbsLenUB.out === 1;

    var modulusBytes = modulusBitsUser \ 8;  // e.g. 2048/8 = 256

    // MOICA TBSes are always > 256 bytes, so the outer SEQUENCE header is
    // always the 4-byte form [0x30, 0x82, len_hi, len_lo]. Length bytes vary.
    issuerTbs[0] === 0x30;
    issuerTbs[1] === 0x82;

    // MOICA issues v3 certs only: pin the [0] EXPLICIT version block
    // [0xa0, 0x03, 0x02, 0x01, 0x02] at offset 4. The serial INTEGER tag is
    // then at offset 9 and its value at offset 11.
    var versionBytes[5] = [0xa0, 0x03, 0x02, 0x01, 0x02];
    for (var i = 0; i < 5; i++) {
        issuerTbs[4 + i] === versionBytes[i];
    }

    var serialValueOff = 11;

    VerifySerialNumber(maxMessageLength, maxSerialNumberLength)(
        issuerTbs,
        serialValueOff,
        serialNumber
    );

    // Validity: offset derived from the DER structure, no prover input.
    // Every read stays inside issuerTbs[0..256), which the pinned 0x30 0x82
    // outer header guarantees to be part of the signed TBS.
    component validity = VerifyValidity(maxSerialNumberLength);
    for (var i = 0; i < 256; i++) {
        validity.tbs[i] <== issuerTbs[i];
    }
    validity.currentTime <== currentTime;

    // Offset of the user modulus's INTEGER tag, derived by continuing the
    // structural walk past the subject Name. Not a prover input.
    component locate = LocateModulus();
    for (var i = 0; i < 512; i++) {
        locate.tbs[i] <== issuerTbs[i];
    }
    locate.subjectOffset <== validity.subjectOffset;
    locate.subjectHeader <== validity.subjectHeader;
    signal tbsModulusTagOffset <== locate.modulusTagOffset;
    AssertSliceInTBS()(tbsModulusTagOffset, 1, actualIssuerTbsLength);

    // DER prefix for an unsigned 2048-bit RSA modulus INTEGER:
    //   [0x02, 0x82, 0x01, 0x01, 0x00]
    // = tag + long-form length-of-length + 2-byte length=257 + sign byte.
    // Bytes +1..+4 are pinned here; the +0 tag is checked by ExtractModulus.
    var modPrefixBytes[4] = [0x82, 0x01, 0x01, 0x00];
    component modPrefixCheck[4];
    for (var i = 0; i < 4; i++) {
        modPrefixCheck[i] = ItemAtIndex(maxMessageLength);
        modPrefixCheck[i].in <== issuerTbs;
        modPrefixCheck[i].index <== tbsModulusTagOffset + 1 + i;
        modPrefixCheck[i].out === modPrefixBytes[i];
    }

    signal tbsModulusOffset <== tbsModulusTagOffset + 5;
    AssertSliceInTBS()(tbsModulusOffset, modulusBytes, actualIssuerTbsLength);

    signal userRsaExtractedModulus[kUser];
    ExtractModulus(maxMessageLength, n, kUser, modulusBitsUser)(
        issuerTbs,
        tbsModulusOffset,
        tbsModulusTagOffset
    ) ==> userRsaExtractedModulus;

    CertRSA256Verify(maxMessageLength, n, kIssuer)(
        issuerTbs,
        issuerTbsLength,
        issuerRsaModulus,
        issuerRsaSignature
    );

    SMTNonMembershipVerifier(smtDepth)(
        smtRoot,
        serialNumber,
        smtSiblings,
        smtOldKey,
        smtOldValue,
        smtIsOld0
    );

    // Hashed over kUser limbs so pkCommit byte-matches UserSigRSA256's output.
    component pkHash = ChunkedPoseidonP256(kUser + 1);
    for (var i = 0; i < kUser; i++) {
        pkHash.inputs[i] <== userRsaExtractedModulus[i];
    }
    pkHash.inputs[kUser] <== pkBlind;
    pkCommit <== pkHash.out;
}

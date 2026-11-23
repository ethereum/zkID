pragma circom 2.2.3;

include "utils/es256.circom";
include "keyless_zk_proofs/hashtofield.circom";
include "@zk-email/circuits/lib/sha.circom";
include "components/claim-decoder.circom";
include "utils/utils.circom";
include "components/payload_matcher.circom";
include "components/ec-extractor.circom";
include "components/device-key-path.circom";
include "components/claim-value-extractor.circom";
include "components/claim-name-extractor.circom";
include "components/claim-value-normalizer.circom";

/// @title JWT
/// @notice Verifies an ES256-signed SD-JWT and extracts normalized claim values.
/// @notice match slots 0 and 1 are reserved for device binding key extraction (x/y patterns).
/// @notice Device-key anchors must be direct members of the signed cnf.jwk object.
/// @notice Disclosure digest matching still assumes the issuer places each digest
///         uniquely in the payload, as an element of the single "_sd" array.
/// @notice Claim arrays are claim-only and map directly to normalizedClaimValues.
/// @notice pubKeyX/pubKeyY (the issuer key the ES256 check runs against) are public
///         inputs of the main component, so they appear in the proof's public IO and
///         a verifier can compare them against the issuers it trusts.
/// @notice decodeFlags/claimFormats are public inputs too. They decide how each claim
///         value was produced, so a verifier comparing a claim against a literal needs
///         them to know what the value means: an undecoded slot holds 0 rather than the
///         claim, and a slot decoded under one format is not comparable to a literal in
///         another.
/// @notice normalizedClaimValues (one integer per claim slot, 0 for undecoded
///         slots) is private: the verifier must not learn claim values, so it
///         reaches Show through the shared-witness commitment, not the public IO.
/// @notice KeyBindingX, KeyBindingY (the device binding public key) are private
///         too: constant across every presentation from this credential, they
///         would be a stable identifier defeating the per-presentation
///         reblinding. The circuit therefore has no public outputs at all.
template JWT(
    maxMessageLength,
    maxB64PayloadLength,
    maxMatches,
    maxSubstringLength,
    maxClaimsLength
) {
    assert(maxMatches >= 2);
    var maxClaims = maxMatches - 2;
    var decodedLen = (maxClaimsLength * 3) / 4;
    var maxPayloadLength = (maxB64PayloadLength * 3) / 4;
    var maxValueLen = decodedLen;

    signal input message[maxMessageLength];
    signal input messageLength;
    signal input periodIndex;

    signal input sig_r;
    signal input sig_s_inverse;
    signal input pubKeyX;
    signal input pubKeyY;

    signal input matchesCount;
    signal input matchSubstring[maxMatches][maxSubstringLength];
    signal input matchLength[maxMatches];
    signal input matchIndex[maxMatches];

    signal input claims[maxClaims][maxClaimsLength];
    signal input claimLengths[maxClaims];
    // decodeFlags[i] = 1 if claim slot i should be decoded and normalized, 0 otherwise.
    signal input decodeFlags[maxClaims];
    // claimFormats[i]: format for normalizing claim slot i (0=bool,1=uint,2=iso_date,3=roc_date,4=string).
    // Only meaningful when decodeFlags[i] = 1.
    signal input claimFormats[maxClaims];

    signal decodedClaims[maxClaims][decodedLen] <== ClaimDecoder(maxClaims, maxClaimsLength)(claims, claimLengths, decodeFlags);
    signal claimHashes[maxClaims][32] <== ClaimHasher(maxClaims, maxClaimsLength)(claims);

    signal claimMatchSubstring[maxClaims][maxSubstringLength];
    signal claimMatchLength[maxClaims];
    for (var i = 0; i < maxClaims; i++) {
        for (var j = 0; j < maxSubstringLength; j++) {
            claimMatchSubstring[i][j] <== matchSubstring[i + 2][j];
        }
        claimMatchLength[i] <== matchLength[i + 2];
    }

    // Compare the claim hashes with the match substrings
    ClaimComparator(maxClaims, maxSubstringLength)(claimHashes, claimLengths, claimMatchSubstring, claimMatchLength);

    // Bind `matchesCount` to actual claim usage. `matchesCount` is a private
    // prover input that gates the payload-inclusion check for each slot
    // (slot i is checked only when i < matchesCount). Without the constraints
    // below a malicious prover could set matchesCount low (e.g. 2) to skip the
    // disclosure-digest inclusion check for a used claim slot, letting an
    // unsigned/attacker disclosure through while device-key slots stay active.
    //
    // Requirement 1: the two device-binding key slots (0,1) must always be
    // checked, so matchesCount >= 2.
    component matchesCountGe2 = GreaterEqThan(log2Ceil(maxMatches) + 1);
    matchesCountGe2.in[0] <== matchesCount;
    matchesCountGe2.in[1] <== 2;
    matchesCountGe2.out === 1;

    // Requirement 2: every used claim slot (claimLengths[i] != 0) maps to match
    // slot i+2, whose payload-inclusion check must be enabled, i.e.
    // (i + 2) < matchesCount.
    component claimUsedIsZero[maxClaims];
    component slotCovered[maxClaims];
    signal claimUsed[maxClaims];
    for (var i = 0; i < maxClaims; i++) {
        claimUsedIsZero[i] = IsZero();
        claimUsedIsZero[i].in <== claimLengths[i];
        claimUsed[i] <== 1 - claimUsedIsZero[i].out;

        slotCovered[i] = LessThan(log2Ceil(maxMatches) + 1);
        slotCovered[i].in[0] <== i + 2;
        slotCovered[i].in[1] <== matchesCount;

        // used claim => slot must be covered
        claimUsed[i] * (1 - slotCovered[i].out) === 0;
    }

    // Verify the issuer signature
    ES256(maxMessageLength)(message, messageLength, sig_r, sig_s_inverse, pubKeyX, pubKeyY);

    // Extract the payload
    signal payload[maxPayloadLength] <== PayloadExtractor(maxMessageLength, maxB64PayloadLength)(
        message,
        messageLength,
        periodIndex
    );

    // Check if the match substrings are in the payload
    signal payloadHash <== PayloadSubstringMatcher(maxPayloadLength, maxMatches, maxSubstringLength)(
        payload,
        matchesCount,
        matchSubstring,
        matchLength,
        matchIndex
    );

    // Pin device-key slots 0/1 to the literal "x":" / "y":" anchors so the
    // path check can use their start indices and known lengths.
    matchLength[0] === 5;
    matchSubstring[0][0] === 34;  // "
    matchSubstring[0][1] === 120; // x
    matchSubstring[0][2] === 34;  // "
    matchSubstring[0][3] === 58;  // :
    matchSubstring[0][4] === 34;  // "

    matchLength[1] === 5;
    matchSubstring[1][0] === 34;  // "
    matchSubstring[1][1] === 121; // y
    matchSubstring[1][2] === 34;  // "
    matchSubstring[1][3] === 58;  // :
    matchSubstring[1][4] === 34;  // "

    // Each anchor must occur exactly once, so slots 0/1 have only one place to point.
    signal xAnchorCount <== CountPatternOccurrences(maxPayloadLength, 5, [34, 120, 34, 58, 34])(payload);
    signal yAnchorCount <== CountPatternOccurrences(maxPayloadLength, 5, [34, 121, 34, 58, 34])(payload);
    xAnchorCount === 1;
    yAnchorCount === 1;

    // Each used digest must be an element of the one "_sd":[ array.
    var SD_LEN = 7;
    signal sdOpen[maxPayloadLength - SD_LEN + 1] <== PatternMatches(maxPayloadLength, SD_LEN, [34, 95, 115, 100, 34, 58, 91])(payload);
    var sdAnchors = 0;
    for (var j = 0; j < maxPayloadLength - SD_LEN + 1; j++) {
        sdAnchors += sdOpen[j];
    }
    signal sdAnchorCount <== sdAnchors;
    sdAnchorCount === 1;

    // sdQuote[j] = 1 if payload[j] is a '"' inside the _sd array (up to the first ']').
    signal isClose[maxPayloadLength];
    signal isQuote[maxPayloadLength];
    signal inSd[maxPayloadLength];
    signal sdQuote[maxPayloadLength];
    for (var j = 0; j < maxPayloadLength; j++) {
        isClose[j] <== IsEqual()([payload[j], 93]);
        isQuote[j] <== IsEqual()([payload[j], 34]);
        inSd[j] <== ((j > 0 ? inSd[j - 1] : 0) + (j >= SD_LEN ? sdOpen[j - SD_LEN] : 0)) * (1 - isClose[j]);
        sdQuote[j] <== inSd[j] * isQuote[j];
    }

    signal digestOpenIdx[maxClaims];
    signal digestCloseIdx[maxClaims];
    signal digestOpenOk[maxClaims];
    signal digestCloseOk[maxClaims];
    for (var i = 0; i < maxClaims; i++) {
        // The quotes around the digest must be inside _sd. Unused slots read index 0.
        digestOpenIdx[i] <== claimUsed[i] * (matchIndex[i + 2] - 1);
        digestCloseIdx[i] <== claimUsed[i] * (matchIndex[i + 2] + matchLength[i + 2]);
        digestOpenOk[i] <== SelectArrayValue(maxPayloadLength)(sdQuote, digestOpenIdx[i], claimUsed[i]);
        digestCloseOk[i] <== SelectArrayValue(maxPayloadLength)(sdQuote, digestCloseIdx[i], claimUsed[i]);
        claimUsed[i] * (1 - digestOpenOk[i]) === 0;
        claimUsed[i] * (1 - digestCloseOk[i]) === 0;
    }

    // Extract the device binding public key from the payload
    component ecExtractor = ECPublicKeyExtractor_Optimized(maxPayloadLength, 32);
    ecExtractor.payload <== payload;
    ecExtractor.xStartIndex <== matchIndex[0] + matchLength[0];
    ecExtractor.yStartIndex <== matchIndex[1] + matchLength[1];

    // Extract and normalize claim values.
    // Claim arrays are claim-only. Each claim is extracted and normalized when decodeFlags[i]=1.
    // Private: normalized values are predicate operands, not verifier outputs.
    // They reach Show through the shared-witness commitment (comm_W_shared),
    // the same path the device key uses. Making them outputs would put them in
    // the public IO and hand the verifier the exact claim (e.g. date of birth).
    component claimExtractors[maxClaims];
    component claimNormalizers[maxClaims];
    signal normalizedClaimValues[maxClaims];

    // Per-slot attribute identity = H(claim_name). The disclosure is
    // ["salt","name","value"], so the name sits next to the value we already
    // extract. Hashing it (same Poseidon-to-field the mdoc path uses for its
    // identifier) binds each slot to an attribute, so a holder cannot answer a
    // policy over one attribute with a friendlier signed value from another
    // slot. Carried to Show via comm_W_shared, checked in eval-predicates
    // against the verifier-supplied predicateClaimIdentifiers. Gated by
    // decodeFlags so inactive slots are 0 (never matched by a real identity).
    // NAME_ID_LEN: fixed width the attribute name is hashed over. 31 = one
    // Poseidon block (HashBytesToFieldWithLen packs 31 bytes/element). Show
    // recomputes H(name) over this SAME width from the verifier-supplied name,
    // so the two hashes match by construction with no off-circuit hashing.
    var NAME_ID_LEN = 31;
    component claimNameExtractors[maxClaims];
    component claimNameHashers[maxClaims];
    component nameFits[maxClaims];
    signal boundedName[maxClaims][NAME_ID_LEN];
    signal claimIdentifierHashes[maxClaims];

    for (var i = 0; i < maxClaims; i++) {
        claimExtractors[i] = ClaimValueExtractor(decodedLen);
        claimExtractors[i].claim    <== decodedClaims[i];
        claimExtractors[i].isActive <== decodeFlags[i];

        claimNormalizers[i] = ClaimValueNormalizer(maxValueLen);
        claimNormalizers[i].value       <== claimExtractors[i].value;
        claimNormalizers[i].valueLength <== claimExtractors[i].valueLength;
        claimNormalizers[i].format      <== claimFormats[i];

        normalizedClaimValues[i] <== claimNormalizers[i].normalizedValue;

        claimNameExtractors[i] = ClaimNameExtractor(decodedLen);
        claimNameExtractors[i].claim    <== decodedClaims[i];
        claimNameExtractors[i].isActive <== decodeFlags[i];

        // Active names must fit in NAME_ID_LEN so no bytes are dropped before hashing.
        nameFits[i] = LessEqThan(log2Ceil(decodedLen + 1));
        nameFits[i].in[0] <== claimNameExtractors[i].nameLength;
        nameFits[i].in[1] <== NAME_ID_LEN;
        decodeFlags[i] * (1 - nameFits[i].out) === 0;

        for (var j = 0; j < NAME_ID_LEN; j++) {
            boundedName[i][j] <== claimNameExtractors[i].name[j];
        }
        claimNameHashers[i] = HashBytesToFieldWithLen(NAME_ID_LEN);
        claimNameHashers[i].in  <== boundedName[i];
        claimNameHashers[i].len <== claimNameExtractors[i].nameLength;

        claimIdentifierHashes[i] <== claimNameHashers[i].hash * decodeFlags[i];
    }

    // The device binding public key is private, for the same reason as the
    // claim values: it is constant across every presentation made from this
    // credential, so publishing it hands the verifier a stable identifier and
    // defeats the per-presentation reblinding. Show reads it from the shared
    // witness commitment to check the nonce signature.
    //
    // This leaves the circuit with no public outputs at all.
    signal KeyBindingX <== ecExtractor.pubKeyX;
    signal KeyBindingY <== ecExtractor.pubKeyY;

    BindDeviceKeyPath(maxPayloadLength)(payload, matchIndex[0], matchIndex[1]);
}

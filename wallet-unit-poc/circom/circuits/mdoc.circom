pragma circom 2.2.3;

include "utils/es256.circom";
include "utils/utils.circom";
include "keyless_zk_proofs/hashtofield.circom";
include "components/mdoc-validity.circom";
include "components/mdoc-claim-verifier.circom";
include "components/mdoc-value-extractor.circom";
include "components/mdoc-device-key.circom";

template MDOC(
    maxCredLen,
    maxPreimageLen,
    maxClaims,
    maxIdentifierLen,
    maxValueLen
) {
    signal input message[maxCredLen];
    signal input messageLength;

    // Issuer public key the ES256 check runs against. Declared public on the main
    // component, so it appears in the proof's public IO and a verifier can compare
    // it against the issuers it trusts.
    signal input pubKeyX;
    signal input pubKeyY;

    signal input sig_r;
    signal input sig_s_inverse;

    signal input validUntilPrefixPos;

    // Position of the COSE `-2: bytes(32)` marker that precedes the device key's
    // x coordinate. The marker bytes themselves are circuit constants.
    signal input deviceKeyPos;

    signal input preimages[maxClaims][maxPreimageLen];
    signal input preimageLengths[maxClaims];
    signal input identifierCbor[maxClaims][maxIdentifierLen];
    signal input identifierLengths[maxClaims];
    signal input identifierPositions[maxClaims];
    signal input digestIds[maxClaims];
    signal input encodedDigestPositions[maxClaims];
    signal input elementValueLabelPositions[maxClaims];
    signal input valueStarts[maxClaims];
    signal input valueEnds[maxClaims];
    // valueTypes and claimFlags decide how each value in normalizedClaimValues was
    // produced, so they are public inputs of the main component: a verifier reading
    // those values needs them to know what the values mean. A slot with claimFlags 0
    // holds 0 rather than the claim, and a slot extracted under one value type is not
    // comparable to a literal in another.
    signal input valueTypes[maxClaims];    // 0=date, 1=string, 2=integer, 3=reveal_digest
    signal input claimFlags[maxClaims];

    signal input digestInputsPadded[maxClaims][maxValueLen];
    signal input digestInputsPaddedLen[maxClaims];

    signal output validUntilDate;
    // Private — see the note in jwt.circom: these are predicate operands that
    // reach Show via comm_W_shared, not values the verifier is meant to learn.
    signal normalizedClaimValues[maxClaims];

    // Carried to Show alongside the values so a predicate can be bound to the
    // requested attribute. Inactive slots are 0 so padding cannot impersonate one.
    signal claimIdentifierHashes[maxClaims];

    // Private, for the same reason as normalizedClaimValues above: the device key
    // reaches Show through comm_W_shared, and the verifier never needs to read it.
    // As a main output it would be public regardless of the `public[...]` list, and
    // it is a per-credential constant that survives reblinding — so two verifiers
    // could join on it and correlate every presentation from one credential.
    signal deviceKeyX;
    signal deviceKeyY;

    // CHECK 1: ECDSA-P256 signature
    ES256(maxCredLen)(message, messageLength, sig_r, sig_s_inverse, pubKeyX, pubKeyY);

    signal messageHash <== HashBytesToFieldWithLen(maxCredLen)(message, messageLength);

    // CHECK 2: validUntil
    validUntilDate <== MdocValidUntil(maxCredLen)(message, messageHash, messageLength, validUntilPrefixPos);

    // CHECK 3: per-claim preimage authenticity + value extraction
    signal preimageHashesPoseidon[maxClaims];

    // Same width show.circom and jwt.circom hash at. Any other width gives a
    // different element for the same attribute and comm_W_shared never matches.
    var NAME_ID_LEN = 31;
    assert(maxIdentifierLen >= NAME_ID_LEN + 1);
    signal nameLengths[maxClaims];
    signal boundedName[maxClaims][NAME_ID_LEN];
    component idNameHashers[maxClaims];

    for (var i = 0; i < maxClaims; i++) {
        // claimFlags[i] must be 0 or 1; fractional values bypass gated assertions.
        claimFlags[i] * (1 - claimFlags[i]) === 0;

        preimageHashesPoseidon[i] <== HashBytesToFieldWithLen(maxPreimageLen)(preimages[i], preimageLengths[i]);

        // MdocClaimVerifier already proved this identifier is in the signed preimage.
        // identifierLengths counts the CBOR header; inactive slots stay at 0.
        nameLengths[i] <== claimFlags[i] * (identifierLengths[i] - 1);

        // Single-byte text-string header only, so the name is identifierCbor[1..].
        // Excludes names of 24 bytes or more, which CBOR frames with two bytes.
        claimFlags[i] * (identifierCbor[i][0] - 96 - nameLengths[i]) === 0;

        for (var j = 0; j < NAME_ID_LEN; j++) {
            boundedName[i][j] <== identifierCbor[i][j + 1];
        }
        idNameHashers[i] = HashBytesToFieldWithLen(NAME_ID_LEN);
        idNameHashers[i].in  <== boundedName[i];
        idNameHashers[i].len <== nameLengths[i];
        claimIdentifierHashes[i] <== idNameHashers[i].hash * claimFlags[i];

        MdocClaimVerifier(maxCredLen, maxPreimageLen, maxIdentifierLen)(
            message,
            messageHash,
            messageLength,
            preimages[i],
            preimageLengths[i],
            preimageHashesPoseidon[i],
            identifierCbor[i],
            identifierLengths[i],
            identifierPositions[i],
            digestIds[i],
            encodedDigestPositions[i],
            claimFlags[i]
        );

        normalizedClaimValues[i] <== MdocValueExtractor(maxPreimageLen, maxValueLen)(
            preimages[i],
            preimageHashesPoseidon[i],
            preimageLengths[i],
            elementValueLabelPositions[i],
            valueStarts[i],
            valueEnds[i],
            valueTypes[i],
            claimFlags[i],
            digestInputsPadded[i],
            digestInputsPaddedLen[i]
        );
    }

    // CHECK 4: device key extraction
    (deviceKeyX, deviceKeyY) <== MdocDeviceKeyExtractor(maxCredLen)(
        message,
        messageLength,
        deviceKeyPos
    );
}

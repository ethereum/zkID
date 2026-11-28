pragma circom 2.2.3;

include "ecdsa/ecdsa.circom";
include "keyless_zk_proofs/hashtofield.circom";
include "components/expression.circom";
include "components/issuer-key.circom";
include "components/revocation.circom";

/// @title Show
/// @notice Verifies device binding and evaluates a logical expression over predicate results.
/// @param nClaims: number of claim field elements available for predicate references
/// @param maxPredicates: maximum number of predicates to evaluate
/// @param maxLogicTokens: capacity of the RPN token array for the logical expression
/// @param valueBits: bit width for claim/compare values in generalized predicates
/// @param revocationMaxDepth: max LeanIMT+ depth of the revocation tree; 0 disables revocation
///
/// Logical expression token encoding (postfix):
///   tokenTypes[i]: 0=REF, 1=AND, 2=OR, 3=NOT
///   tokenValues[i]: predicate index for REF, else 0
template Show(nClaims, maxPredicates, maxLogicTokens, valueBits, revocationMaxDepth) {
    // Fixed width the attribute name is hashed over; must equal the credential
    // circuit's NAME_ID_LEN (jwt.circom) so identities match by construction.
    var NAME_ID_LEN = 31;

    signal input deviceKeyX; // Device binding public key x-coordinate.
    signal input deviceKeyY; // Device binding public key y-coordinate.
    signal input messageHash; // Scalar-field reduced hash of the verifier nonce.
    signal input sig_r; // ECDSA signature r value over messageHash.
    signal input sig_s_inverse; // Multiplicative inverse of signature s in the scalar field.

    // Generalized predicate phase inputs
    signal input predicateLen; // Number of active predicates.
    signal input claimValues[nClaims]; // Normalized claim values addressable by reference index.
    signal input predicateClaimRefs[maxPredicates]; // Left-hand claim reference per predicate.
    signal input predicateOps[maxPredicates]; // Operator per predicate: 0<=, 1>=, 2==.
    signal input predicateRhsIsRef[maxPredicates]; // Right-hand side (RHS) mode per predicate: 0=literal, 1=claim reference.
    signal input predicateRhsValues[maxPredicates]; // RHS operand: claim index when predicateRhsIsRef is 1, literal value when 0.
    signal input claimIdentifierHashes[nClaims]; // Attribute identity per slot, bound via the shared segment.
    // The verifier names the attribute each operand must be, as raw bytes. Show
    // hashes them here with the SAME HashBytesToFieldWithLen the credential
    // circuit uses to derive claimIdentifierHashes, so the required identity
    // matches by construction and no hash is computed off-circuit. NAME_ID_LEN
    // must equal the credential circuit's (jwt.circom / mdoc).
    signal input predicateClaimNames[maxPredicates][NAME_ID_LEN]; // Public: LHS attribute name bytes per predicate.
    signal input predicateClaimNameLens[maxPredicates];           // Public: LHS name length per predicate.
    signal input predicateRhsClaimNames[maxPredicates][NAME_ID_LEN]; // Public: RHS attribute name bytes per predicate.
    signal input predicateRhsClaimNameLens[maxPredicates];           // Public: RHS name length per predicate.

    // Logical expression over predicate results in Reverse Polish Notation.
    signal input tokenTypes[maxLogicTokens]; // Postfix token kind: 0=REF, 1=AND, 2=OR, 3=NOT.
    signal input tokenValues[maxLogicTokens]; // Token payload: predicate index for REF tokens.
    signal input exprLen; // Number of active expression tokens.

    // Output: result of the logical expression over all predicate results
    signal output expressionResult;

    component ecdsa = ECDSA();
    ecdsa.s_inverse <== sig_s_inverse;
    ecdsa.r <== sig_r;
    ecdsa.m <== messageHash;
    ecdsa.pubKeyX <== deviceKeyX;
    ecdsa.pubKeyY <== deviceKeyY;

    // Hash the verifier-supplied attribute names into the required identities,
    // using the identical hash the credential circuit used for the slots.
    component lhsNameHashers[maxPredicates];
    component rhsNameHashers[maxPredicates];
    signal predicateClaimIdentifiers[maxPredicates];
    signal predicateRhsClaimIdentifiers[maxPredicates];
    for (var p = 0; p < maxPredicates; p++) {
        lhsNameHashers[p] = HashBytesToFieldWithLen(NAME_ID_LEN);
        lhsNameHashers[p].in  <== predicateClaimNames[p];
        lhsNameHashers[p].len <== predicateClaimNameLens[p];
        predicateClaimIdentifiers[p] <== lhsNameHashers[p].hash;

        rhsNameHashers[p] = HashBytesToFieldWithLen(NAME_ID_LEN);
        rhsNameHashers[p].in  <== predicateRhsClaimNames[p];
        rhsNameHashers[p].len <== predicateRhsClaimNameLens[p];
        predicateRhsClaimIdentifiers[p] <== rhsNameHashers[p].hash;
    }

    // Evaluate generalized predicates and then the postfix boolean expression
    component expressionEval = ExpressionEvaluator(nClaims, maxPredicates, maxLogicTokens, valueBits);
    expressionEval.claimValues <== claimValues;
    expressionEval.predicateLen <== predicateLen;
    expressionEval.predicateClaimRefs <== predicateClaimRefs;
    expressionEval.predicateOps <== predicateOps;
    expressionEval.predicateRhsIsRef <== predicateRhsIsRef;
    expressionEval.predicateRhsValues <== predicateRhsValues;
    expressionEval.claimIdentifierHashes <== claimIdentifierHashes;
    expressionEval.predicateClaimIdentifiers <== predicateClaimIdentifiers;
    expressionEval.predicateRhsClaimIdentifiers <== predicateRhsClaimIdentifiers;
    expressionEval.tokenTypes <== tokenTypes;
    expressionEval.tokenValues <== tokenValues;
    expressionEval.exprLen <== exprLen;
    expressionResult <== expressionEval.finalResult;

    // Revocation: the commitment sha256(issuer key || revocation value || 3) must be absent
    // from the revocation tree. Both the key and the issuer-signed value come from
    // the credential circuit through the shared witness, so the commitment is the one
    // of the credential that circuit verified.
    if (revocationMaxDepth > 0) {
        signal input issuerKeyX; // Credential issuer key, shared via comm_W_shared.
        signal input issuerKeyY;
        signal input revocationValue[2]; // [hi, lo] signed revocation value, shared via comm_W_shared.
        signal input revocationLeafValue[2];
        signal input revocationLeafNextValue[2];
        signal input revocationLeafIndex;
        signal input revocationDepth;
        signal input revocationSiblings[revocationMaxDepth][2];

        signal output revocationRoot[2]; // [hi, lo]; [0, 0] for an empty registry.

        // Canonical be32(issuerKeyX) || be32(issuerKeyY).
        signal issuerKeyBits[512] <== IssuerKeyBits()(issuerKeyX, issuerKeyY);

        component revocation = RevocationCheck(revocationMaxDepth);
        revocation.issuerKeyBits <== issuerKeyBits;
        revocation.value <== revocationValue;
        revocation.leafValue <== revocationLeafValue;
        revocation.leafNextValue <== revocationLeafNextValue;
        revocation.leafIndex <== revocationLeafIndex;
        revocation.depth <== revocationDepth;
        revocation.siblings <== revocationSiblings;
        revocationRoot <== revocation.root;
    }
}


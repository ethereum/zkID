pragma circom 2.1.2;

include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/gates.circom";

/**
 *  Secp256r1AddIncomplete
 *  ======================
 *
 *  Adds two points (xP, yP) and (xQ, yQ) on the secp256r1 curve. This function 
 *  only works for points where xP != xQ and are not at infinity. We can implement 
 *  the raw formulae for this operation as we are doing right field arithmetic 
 *  (we are doing secp256r1 base field arithmetic in the T256 scalar field, 
 *  which are equal). Should work for any short Weierstrass curve (Pasta, P-256).
 *
 *  Modified from https://github.com/personaelabs/spartan-ecdsa/blob/main/packages/circuits/eff_ecdsa_membership/secp256k1/add.circom
 */
template Secp256r1AddIncomplete() {
    signal input xP;
    signal input yP;
    signal input xQ;
    signal input yQ;
    signal output outX;
    signal output outY;

    signal lambda;
    signal dx;
    signal dy;

    dx <== xP - xQ;
    dy <== yP - yQ;

    lambda <-- dy / dx;
    dx * lambda === dy;

    outX <== lambda * lambda - xP - xQ;
    outY <== lambda * (xP - outX) - yP;
}

/**
 *  Secp256r1AddComplete
 *  ====================
 *
 *  Implements https://zcash.github.io/halo2/design/gadgets/ecc/addition.html#complete-addition
 *  so we can add any pair of points. Assumes (0, 0) is not a valid point (which 
 *  is true for secp256r1) and is used as the point at infinity.
 *
 *  Modified from https://github.com/personaelabs/spartan-ecdsa/blob/main/packages/circuits/eff_ecdsa_membership/secp256k1/add.circom
 */
template Secp256r1AddComplete() {
    signal input xP;
    signal input yP;
    signal input xQ;
    signal input yQ;

    signal output outX;
    signal output outY;

    signal xPSquared <== xP * xP;

    component isXEqual = IsEqual();
    isXEqual.in[0] <== xP;
    isXEqual.in[1] <== xQ;

    component isXpZero = IsZero();
    isXpZero.in <== xP;

    component isYpZero = IsZero();
    isYpZero.in <== yP;

    component isXqZero = IsZero();
    isXqZero.in <== xQ;

    component isYqZero = IsZero();
    isYqZero.in <== yQ;

    // (0,0) is the only infinity encoding - x==0 alone is not infinity,
    // since P-256's b is a QR mod p, so (0, y) with y^2=b is a real point.
    component isPInf = AND();
    isPInf.a <== isXpZero.out;
    isPInf.b <== isYpZero.out;

    component isQInf = AND();
    isQInf.a <== isXqZero.out;
    isQInf.b <== isYqZero.out;

    component isXEitherZero = IsZero();
    isXEitherZero.in <== (1 - isPInf.out) * (1 - isQInf.out);

    // dx = xQ - xP
    // dy = xP != xQ ? yQ - yP : 0
    // lambdaA = xP != xQ ? (yQ - yP) / (xQ - xP) : 0
    signal dx <== xQ - xP;
    signal dy <== (yQ - yP) * (1 - isXEqual.out);
    signal lambdaA <-- ((yQ - yP) / dx) * (1 - isXEqual.out);
    dx * lambdaA === dy;
    // When xP == xQ, dx = dy = 0 and the line above holds for every lambdaA.
    // lambdaA is added into lambda, so pin it to 0 there (lambdaB is the slope).
    lambdaA * isXEqual.out === 0;

    // lambdaB = (3 * xP^2) / (2 * yP)
    // P at infinity (0, 0) has no tangent: relax the constraint (lambdaB = 0)
    // instead of requiring 0 === -3. The infinity branches below ignore lambda.
    signal tangentNum <== (3 * xPSquared - 3) * (1 - isPInf.out);
    signal lambdaB <-- tangentNum / (2 * yP + isPInf.out);
    lambdaB * 2 * yP === tangentNum;

    // lambda = xP != xQ ? lambdaA : lambdaB
    signal lambda <== (lambdaB * isXEqual.out) + lambdaA;

    // outAx = lambda^2 - xP - xQ
    // outAy = lambda * (xP - outAx) - yP
    signal outAx <== lambda * lambda - xP - xQ;
    signal outAy <== lambda * (xP - outAx) - yP;

    // (outBx, outBy) = xP != 0 and xQ != 0 ? (outAx, outAy) : (0, 0)
    signal outBx <== outAx * (1 - isXEitherZero.out);
    signal outBy <== outAy * (1 - isXEitherZero.out);

    //(outCx, outCy) = P infinity ? (xQ, yQ) : (0, 0)
    signal outCx <== isPInf.out * xQ;
    signal outCy <== isPInf.out * yQ;

    // (outDx, outDy) = Q infinity ? (xP, yP) : (0, 0)
    signal outDx <== isQInf.out * xP;
    signal outDy <== isQInf.out * yP;

    // zeroizeA = (xP = xQ and yP = -yQ) ? 1 : 0
    component isYSumZero = IsZero();
    isYSumZero.in <== yP + yQ;

    component zeroizeA = AND();
    zeroizeA.a <== isXEqual.out;
    zeroizeA.b <== isYSumZero.out;

    // zeroizeB = (P infinity and Q infinity) ? 1 : 0
    component zeroizeB = AND();
    zeroizeB.a <== isPInf.out;
    zeroizeB.b <== isQInf.out;

    // zeroize = (xP = xQ and yP = -yQ) or (xP = 0 and xQ = 0) ? 1 : 0
    // for this case we want to output the point at infinity (0, 0)
    component zeroize = OR();
    zeroize.a <== zeroizeA.out;
    zeroize.b <== zeroizeB.out;

    // The below three conditionals are mutually exclusive when zeroize = 0, 
    // so we can safely sum the outputs.
    // outBx != 0 iff xP != 0 and xQ != 0
    // outCx != 0 iff xP = 0
    // outDx != 0 iff xQ = 0
    outX <== (outBx + outCx + outDx) * (1 - zeroize.out);
    outY <== (outBy + outCy + outDy) * (1 - zeroize.out);
}

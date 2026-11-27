import { strict as assert } from "assert";
import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";

const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

// Standard NIST P-256 generator G (matches ecdsa/ecdsa.circom)
const GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
const GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;

// Matches OpenAC.P256Addition.p256GenTangent in DoublingUnderconstraint.lean
const GEN_TANGENT = 0xa249bcb3191802d3cb56fc75a8731f848e7b2caf080f3477a4e4d904a671af9dn;

// Expected 2G and 3G on P-256
const G2X = 0x7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978n;
const G2Y = 0x07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1n;
const G3X = 0x5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6cn;
const G3Y = 0x8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032n;

// Forged output on (G, G) with lambdaA = 1 from p256GeneratorForgedDoubling in Lean
const FORGED_DELTA1_X = 0xc185f47fbf335525210030ee559b59ccdd7fc33f88108424efd4fb059449f8b4n;
const FORGED_DELTA1_Y = 0x687b37d045b812763e0b48ac6d0ebf2b686571b33323f83edf50a5c8cf2550can;

type SignalMap = Map<string, number>;
type SymbolInfo = { varIdx: number };

const modP = (x: bigint): bigint => ((x % P) + P) % P;

function isOnP256(x: bigint, y: bigint): boolean {
  return modP(y * y - (x * x * x - 3n * x + B)) === 0n;
}

function affineFromSlope(xp: bigint, yp: bigint, xq: bigint, slope: bigint): { x: bigint; y: bigint } {
  const x = modP(slope * slope - xp - xq);
  const y = modP(slope * (xp - x) - yp);
  return { x, y };
}

async function readSignalMap(circuit: WitnessTester<any, any>): Promise<SignalMap> {
  const tester = circuit as unknown as {
    loadSymbols: () => Promise<void>;
    symbols?: Record<string, SymbolInfo>;
  };
  await tester.loadSymbols();

  const map = new Map<string, number>();
  for (const [signalName, info] of Object.entries(tester.symbols ?? {})) {
    if (Number.isInteger(info.varIdx) && info.varIdx >= 0) {
      map.set(signalName, info.varIdx);
    }
  }
  return map;
}

function setSignal(witness: bigint[], signalMap: SignalMap, name: string, value: bigint): void {
  const idx = signalMap.get(name);
  assert.ok(idx !== undefined && idx > 0, `expected retained signal ${name}`);
  witness[idx] = modP(value);
}

/**
 * Rebuild only the slope and downstream output signals of a finite-point
 * Secp256r1AddComplete witness after perturbing `main.lambdaA` by `delta`.
 * Input coordinates (xP, yP, xQ, yQ) are never modified.
 */
function forgeWithLambdaA(
  honestWitness: bigint[],
  signalMap: SignalMap,
  xp: bigint,
  yp: bigint,
  xq: bigint,
  newLambdaA: bigint,
  newSlope: bigint,
): { witness: bigint[]; outX: bigint; outY: bigint } {
  const forged = honestWitness.slice();
  const { x: outX, y: outY } = affineFromSlope(xp, yp, xq, newSlope);

  setSignal(forged, signalMap, "main.lambdaA", newLambdaA);
  setSignal(forged, signalMap, "main.lambda", newSlope);
  setSignal(forged, signalMap, "main.outAx", outX);
  setSignal(forged, signalMap, "main.outAy", outY);
  setSignal(forged, signalMap, "main.outBx", outX);
  setSignal(forged, signalMap, "main.outBy", outY);
  setSignal(forged, signalMap, "main.outX", outX);
  setSignal(forged, signalMap, "main.outY", outY);

  return { witness: forged, outX, outY };
}

describe("Secp256r1AddComplete doubling underconstraint", () => {
  let circuit!: WitnessTester<["xP", "yP", "xQ", "yQ"], ["outX", "outY"]>;
  let signalMap!: SignalMap;

  before(async () => {
    assert.ok(isOnP256(GX, GY), "G must lie on P-256");
    assert.ok(isOnP256(G2X, G2Y), "2G must lie on P-256");
    assert.ok(isOnP256(G3X, G3Y), "3G must lie on P-256");

    circuit = await circomkit.WitnessTester("Secp256r1AddCompleteUnderconstraint", {
      file: "ecdsa/p256/add",
      template: "Secp256r1AddComplete",
      params: [],
      recompile: true,
    });
    signalMap = await readSignalMap(circuit);
  });

  it("computes 2G honestly when doubling G with lambdaA = 0", async () => {
    const witness = await circuit.calculateWitness({ xP: GX, yP: GY, xQ: GX, yQ: GY });
    await circuit.expectConstraintPass(witness);

    const signals = await circuit.readWitness(witness, [
      "main.outX",
      "main.outY",
      "main.lambdaA",
      "main.lambdaB",
      "main.lambda",
    ]);
    assert.strictEqual(signals["main.lambdaA"], 0n);
    assert.strictEqual(signals["main.lambdaB"], GEN_TANGENT);
    assert.strictEqual(signals["main.lambda"], GEN_TANGENT);
    assert.strictEqual(signals["main.outX"], G2X);
    assert.strictEqual(signals["main.outY"], G2Y);
  });

  it("rejects tampering lambdaA on distinct finite points (G, 2G)", async () => {
    const witness = await circuit.calculateWitness({ xP: GX, yP: GY, xQ: G2X, yQ: G2Y });
    await circuit.expectConstraintPass(witness);

    const signals = await circuit.readWitness(witness, ["main.outX", "main.outY", "main.lambdaA", "main.lambda"]);
    assert.strictEqual(signals["main.outX"], G3X);
    assert.strictEqual(signals["main.outY"], G3Y);

    const tamperedLambdaA = modP(signals["main.lambdaA"] + 1n);
    const { witness: tampered } = forgeWithLambdaA(
      witness,
      signalMap,
      GX,
      GY,
      G2X,
      tamperedLambdaA,
      tamperedLambdaA,
    );
    await circuit.expectConstraintFail(tampered);
  });

  it("rejects a doubling witness on (G, G) with nonzero lambdaA (delta = 1)", async () => {
    const honest = await circuit.calculateWitness({ xP: GX, yP: GY, xQ: GX, yQ: GY });
    await circuit.expectConstraintPass(honest);

    const { witness: forged, outX, outY } = forgeWithLambdaA(
      honest,
      signalMap,
      GX,
      GY,
      GX,
      1n,
      modP(GEN_TANGENT + 1n),
    );

    assert.strictEqual(outX, FORGED_DELTA1_X);
    assert.strictEqual(outY, FORGED_DELTA1_Y);
    assert.notStrictEqual(outX, G2X);
    assert.strictEqual(isOnP256(outX, outY), false, "forged output is off-curve");

    // Inputs are unchanged (G, G), but main.lambdaA = 1 shifts the slope and
    // yields an off-curve point. The constraint system must reject this witness.
    await circuit.expectConstraintFail(forged);
  });

  it("rejects a doubling witness on (G, G) with an arbitrary chosen slope (lambda = 0)", async () => {
    const honest = await circuit.calculateWitness({ xP: GX, yP: GY, xQ: GX, yQ: GY });
    await circuit.expectConstraintPass(honest);

    const cancelTangent = modP(-GEN_TANGENT);
    const { witness: forged, outX, outY } = forgeWithLambdaA(
      honest,
      signalMap,
      GX,
      GY,
      GX,
      cancelTangent,
      0n,
    );

    assert.strictEqual(outX, modP(-2n * GX));
    assert.strictEqual(outY, modP(-GY));
    assert.notStrictEqual(outX, G2X);
    assert.strictEqual(isOnP256(outX, outY), false, "forged output is off-curve");

    await circuit.expectConstraintFail(forged);
  });
});

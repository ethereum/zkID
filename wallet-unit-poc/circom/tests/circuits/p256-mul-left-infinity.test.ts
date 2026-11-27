import { strict as assert } from "assert";
import { p256 } from "@noble/curves/p256";
import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";

const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const Q = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

const G = p256.ProjectivePoint.BASE;
const { x: GX, y: GY } = G.toAffine();

function bigintTo32BytesBE(value: bigint): Uint8Array {
  return Uint8Array.from(Buffer.from(value.toString(16).padStart(64, "0"), "hex"));
}

function modQ(x: bigint): bigint {
  return ((x % Q) + Q) % Q;
}

function modInv(a: bigint, m: bigint): bigint {
  let [oldR, r] = [((a % m) + m) % m, m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  assert.strictEqual(oldR, 1n);
  return ((oldS % m) + m) % m;
}

describe("Secp256r1Mul left-infinity completeness bug (s in {0, 1, q-2, q-1})", () => {
  let mulCircuit!: WitnessTester<["scalar", "xP", "yP"], ["outX", "outY"]>;
  let ecdsaCircuit!: WitnessTester<["s_inverse", "r", "m", "pubKeyX", "pubKeyY"], []>;

  before(async () => {
    mulCircuit = await circomkit.WitnessTester("Secp256r1MulLeftInf", {
      file: "ecdsa/p256/mul",
      template: "Secp256r1Mul",
      params: [],
      recompile: true,
    });
    ecdsaCircuit = await circomkit.WitnessTester("ECDSAMulLeftInf", {
      file: "ecdsa/ecdsa",
      template: "ECDSA",
      params: [],
      recompile: true,
    });
  });

  it("computes s * G honestly for boundary neighbors s = 2 and s = q - 3", async () => {
    for (const scalar of [2n, Q - 3n]) {
      const expected = G.multiply(scalar).toAffine();
      const witness = await mulCircuit.calculateWitness({ scalar, xP: GX, yP: GY });
      await mulCircuit.expectConstraintPass(witness);
      const out = await mulCircuit.readWitness(witness, ["main.outX", "main.outY"]);
      assert.strictEqual(out["main.outX"], expected.x);
      assert.strictEqual(out["main.outY"], expected.y);
    }
  });

  // For s in {0, 1, q - 2, q - 1}, accComplete[1] hits q * P = O = (0, 0),
  // which is then fed as the left operand to accComplete[2] (Secp256r1AddComplete),
  // where `lambdaB * 2 * yP === 3 * xPSquared - 3` becomes `0 === -3` (unsatisfiable).
  const failingScalars: Array<{ label: string; scalar: bigint; expectedX: bigint; expectedY: bigint }> = [
    { label: "0", scalar: 0n, expectedX: 0n, expectedY: 0n },
    { label: "1", scalar: 1n, expectedX: GX, expectedY: GY },
    { label: "q - 2", scalar: Q - 2n, expectedX: G.multiply(Q - 2n).toAffine().x, expectedY: G.multiply(Q - 2n).toAffine().y },
    { label: "q - 1", scalar: Q - 1n, expectedX: GX, expectedY: P - GY },
  ];

  for (const { label, scalar, expectedX, expectedY } of failingScalars) {
    it(`computes (${label}) * G without hitting left-infinity in accComplete[2]`, async () => {
      const witness = await mulCircuit.calculateWitness({ scalar, xP: GX, yP: GY });
      await mulCircuit.expectConstraintPass(witness);
      const out = await mulCircuit.readWitness(witness, ["main.outX", "main.outY"]);
      assert.strictEqual(out["main.outX"], expectedX);
      assert.strictEqual(out["main.outY"], expectedY);
    });
  }

  it("accepts a FIPS 186-5 valid low-S ECDSA signature with m = 0", async () => {
    const d = 5n;
    const pub = G.multiply(d);
    let k = 7n;
    let R = G.multiply(k).toAffine();
    let r = modQ(R.x);
    let s = modQ(modInv(k, Q) * r * d);
    if (s > Q / 2n) {
      k = Q - k;
      R = G.multiply(k).toAffine();
      r = modQ(R.x);
      s = modQ(modInv(k, Q) * r * d);
    }
    const sInverse = modInv(s, Q);
    assert.ok(s > 0n && s <= Q / 2n, "low-S");
    assert.ok(r >= 2n && r <= Q - 3n && sInverse >= 2n && sInverse <= Q - 3n);

    const zeroDigest = new Uint8Array(32);
    const sig = new p256.Signature(r, s);
    assert.strictEqual(p256.verify(sig, zeroDigest, pub.toRawBytes(), { prehash: false }), true);

    const { x: pubKeyX, y: pubKeyY } = pub.toAffine();
    const witness = await ecdsaCircuit.calculateWitness({
      s_inverse: sInverse,
      r,
      m: 0n,
      pubKeyX,
      pubKeyY,
    });
    await ecdsaCircuit.expectConstraintPass(witness);
  });

  it("accepts a FIPS 186-5 valid low-S ECDSA signature with s = (q - 1) / 2 (s_inverse = q - 2)", async () => {
    const d = 5n;
    const pub = G.multiply(d);
    const k = 7n;
    const R = G.multiply(k).toAffine();
    const r = modQ(R.x);
    const s = (Q - 1n) / 2n; // canonical low-S, with s^-1 = q - 2 mod q
    const sInverse = modInv(s, Q);
    assert.strictEqual(sInverse, Q - 2n);
    assert.ok(s <= Q / 2n, "low-S");

    // Pick m so s = k^-1 * (m + r * d) mod q holds identically
    const m = modQ(k * s - r * d);
    assert.ok(m >= 2n && m <= Q - 3n && r >= 2n && r <= Q - 3n);

    const sig = new p256.Signature(r, s);
    assert.strictEqual(p256.verify(sig, bigintTo32BytesBE(m), pub.toRawBytes(), { prehash: false }), true);

    const { x: pubKeyX, y: pubKeyY } = pub.toAffine();
    const witness = await ecdsaCircuit.calculateWitness({
      s_inverse: sInverse,
      r,
      m,
      pubKeyX,
      pubKeyY,
    });
    await ecdsaCircuit.expectConstraintPass(witness);
  });
});

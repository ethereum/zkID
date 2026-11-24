import { strict as assert } from "assert";
import { p256 } from "@noble/curves/p256";
import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";

const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const Q = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

// Concrete FIPS 186-5 valid low-S P-256 signature matching
// OpenAC.EcdsaCircuit.HighX in show/ecdsa/HighXRejection.lean:
//   u1 = (m * s^-1) mod q = 2, u2 = (r * s^-1) mod q = 4
//   R  = u1*G + u2*Q_a has R.x = q + 3 in [q, p), so R.x mod q = r = 3.
const HIGH_X = {
  r: 3n,
  s: 0x3fffffffc00000003fffffffffffffffef39beab69c5e7a13cee72b0bf18c955n,
  sInverse: 0xaaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e2n,
  digest: 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192aan,
  pubKeyX: 0xc5afde1d3db8a674106a11046a884534a788fb66fd641258fc200bac9350a1b4n,
  pubKeyY: 0x875439bb9e2897810b1e5452434eb5d203b24665232f015ac975545799266a1en,
  expectedRx: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632554n,
  expectedRy: 0x484f0c0fda434ef0a808458914f328715d7a545e198ac7eee31dffe861b5d23fn,
} as const;

function bigintTo32BytesBE(value: bigint): Uint8Array {
  const hex = value.toString(16).padStart(64, "0");
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

function modInv(a: bigint, m: bigint): bigint {
  let [oldR, r] = [((a % m) + m) % m, m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  assert.strictEqual(oldR, 1n, "inverse must exist");
  return ((oldS % m) + m) % m;
}

describe("ECDSA final comparison R.outX mod q", () => {
  let circuit!: WitnessTester<["s_inverse", "r", "m", "pubKeyX", "pubKeyY"], []>;

  before(async () => {
    circuit = await circomkit.WitnessTester("ECDSAHighX", {
      file: "ecdsa/ecdsa",
      template: "ECDSA",
      params: [],
      recompile: true,
    });
  });

  it("accepts a valid P-256 signature whose verification point has R.x < q", async () => {
    const privKey = bigintTo32BytesBE(0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef1n);
    const digest = bigintTo32BytesBE(0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20n);
    const sig = p256.sign(digest, privKey, { prehash: false });
    const pub = p256.ProjectivePoint.fromPrivateKey(privKey);

    assert.strictEqual(p256.verify(sig, digest, pub.toRawBytes(), { prehash: false }), true);

    const m = BigInt("0x" + Buffer.from(digest).toString("hex")) % Q;
    const sInverse = modInv(sig.s, Q);
    const R = p256.ProjectivePoint.BASE.multiply((m * sInverse) % Q).add(
      pub.multiply((sig.r * sInverse) % Q),
    );
    assert.ok(R.toAffine().x < Q, "control signature must have R.x < q");

    const { x: pubKeyX, y: pubKeyY } = pub.toAffine();
    const witness = await circuit.calculateWitness({
      s_inverse: sInverse,
      r: sig.r,
      m,
      pubKeyX,
      pubKeyY,
    });
    await circuit.expectConstraintPass(witness);
  });

  it("accepts a FIPS 186-5 valid P-256 signature whose verification point has q <= R.x < p", async () => {
    const pub = p256.ProjectivePoint.fromAffine({
      x: HIGH_X.pubKeyX,
      y: HIGH_X.pubKeyY,
    });
    pub.assertValidity();

    assert.ok(HIGH_X.r > 0n && HIGH_X.r < Q);
    assert.ok(HIGH_X.s > 0n && HIGH_X.s <= Q / 2n, "signature must be canonical low-S");
    assert.strictEqual((HIGH_X.s * HIGH_X.sInverse) % Q, 1n);
    assert.strictEqual((HIGH_X.digest * HIGH_X.sInverse) % Q, 2n);
    assert.strictEqual((HIGH_X.r * HIGH_X.sInverse) % Q, 4n);

    // Check R = 2*G + 4*Q_a has q <= R.x < p and R.x mod q = r.
    const R = p256.ProjectivePoint.BASE.multiply(2n).add(pub.multiply(4n)).toAffine();
    assert.strictEqual(R.x, HIGH_X.expectedRx);
    assert.strictEqual(R.y, HIGH_X.expectedRy);
    assert.ok(R.x >= Q && R.x < P, "verification point x must lie in [q, p)");
    assert.strictEqual(R.x % Q, HIGH_X.r);

    // Standard ECDSA verification accepts this signature (even with strict low-S).
    const sig = new p256.Signature(HIGH_X.r, HIGH_X.s);
    const digestBytes = bigintTo32BytesBE(HIGH_X.digest);
    assert.strictEqual(p256.verify(sig, digestBytes, pub.toRawBytes(), { prehash: false }), true);

    // The circuit computes R.outX = q + 3 and rejects at `r === R.outX` (ecdsa.circom:100)
    // because it compares field elements in F_p without reducing R.outX modulo q.
    const witness = await circuit.calculateWitness({
      s_inverse: HIGH_X.sInverse,
      r: HIGH_X.r,
      m: HIGH_X.digest,
      pubKeyX: HIGH_X.pubKeyX,
      pubKeyY: HIGH_X.pubKeyY,
    });
    await circuit.expectConstraintPass(witness);
  });
});

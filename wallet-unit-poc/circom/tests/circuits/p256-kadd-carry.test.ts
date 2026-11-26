import { strict as assert } from "assert";
import { p256 } from "@noble/curves/p256";
import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";

const Q = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const LIMB_BASE = 1n << 128n;
const T_Q = 115792089183396302101823908890127239206723925782630956645386934114223894448802n; // (q - 2^256) mod q
const T_Q_LO = T_Q & (LIMB_BASE - 1n);
const CARRY_THRESHOLD = LIMB_BASE - T_Q_LO; // smallest scalar with slo + tQlo >= 2^128
const MAX_FAILING_SCALAR = (((Q - T_Q) >> 128n) << 128n) - 1n; // largest scalar with s + tQ < q and slo + tQlo >= 2^128

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

function unpackBitsLE(symbols: Record<string, bigint>): bigint {
  let acc = 0n;
  for (let i = 0; i < 256; i++) {
    const bit = symbols[`main.out[${i}]`];
    assert.ok(bit === 0n || bit === 1n, `expected bit at index ${i}`);
    acc |= bit << BigInt(i);
  }
  return acc;
}

describe("K_add missing low-limb carry propagation (s < q - tQ with slo + tQlo >= 2^128)", () => {
  let kAddCircuit!: WitnessTester<["s"], ["out"]>;
  let mulCircuit!: WitnessTester<["scalar", "xP", "yP"], ["outX", "outY"]>;
  let ecdsaCircuit!: WitnessTester<["s_inverse", "r", "m", "pubKeyX", "pubKeyY"], []>;

  before(async () => {
    kAddCircuit = await circomkit.WitnessTester("KAddCarry", {
      file: "ecdsa/p256/mul",
      template: "K_add",
      params: [],
      recompile: true,
    });
    mulCircuit = await circomkit.WitnessTester("Secp256r1MulKAddCarry", {
      file: "ecdsa/p256/mul",
      template: "Secp256r1Mul",
      params: [],
      recompile: true,
    });
    ecdsaCircuit = await circomkit.WitnessTester("ECDSAKAddCarry", {
      file: "ecdsa/ecdsa",
      template: "ECDSA",
      params: [],
      recompile: true,
    });
  });

  const outNames = Array.from({ length: 256 }, (_, i) => `main.out[${i}]`);

  it("recodes boundary controls s = 2^128 - tQlo - 1 (no carry) and s = q - tQ (quotient = 1)", async () => {
    for (const s of [CARRY_THRESHOLD - 1n, Q - T_Q]) {
      const witness = await kAddCircuit.calculateWitness({ s });
      await kAddCircuit.expectConstraintPass(witness);
      const out = await kAddCircuit.readWitness(witness, outNames);
      assert.strictEqual(unpackBitsLE(out), modQ(s + T_Q));
    }
  });

  it("computes (2^128 - tQlo - 1) * G honestly in Secp256r1Mul (control)", async () => {
    const scalar = CARRY_THRESHOLD - 1n;
    const expected = G.multiply(scalar).toAffine();
    const witness = await mulCircuit.calculateWitness({ scalar, xP: GX, yP: GY });
    await mulCircuit.expectConstraintPass(witness);
    const out = await mulCircuit.readWitness(witness, ["main.outX", "main.outY"]);
    assert.strictEqual(out["main.outX"], expected.x);
    assert.strictEqual(out["main.outY"], expected.y);
  });

  // In K_add, carry = (slo + tQlo) >> 128 is folded into (alo, ahi) for the
  // comparison against q, but lines 233-241 compute klo/khi from raw (slo + tQlo, shi + tQhi).
  // Whenever s + tQ < q (isQuotientOne = 0, borrow = 0) and slo + tQlo >= 2^128,
  // klo = slo + tQlo >= 2^128 overflows kloBits = Num2Bits(128).
  const failingScalars: Array<{ label: string; s: bigint }> = [
    { label: "2^128 - tQlo (smallest failing scalar)", s: CARRY_THRESHOLD },
    { label: "2^128 - 1", s: LIMB_BASE - 1n },
    { label: "((q - tQ) >> 128) * 2^128 - 1 (largest failing scalar)", s: MAX_FAILING_SCALAR },
  ];

  for (const { label, s } of failingScalars) {
    it(`K_add recodes valid canonical scalar s = ${label}`, async () => {
      assert.ok(s > 1n && s < Q - T_Q, "canonical scalar with isQuotientOne = 0");
      assert.ok((s & (LIMB_BASE - 1n)) + T_Q_LO >= LIMB_BASE, "low-limb addition carries");

      const witness = await kAddCircuit.calculateWitness({ s });
      await kAddCircuit.expectConstraintPass(witness);
      const out = await kAddCircuit.readWitness(witness, outNames);
      assert.strictEqual(unpackBitsLE(out), modQ(s + T_Q));
    });
  }

  it("Secp256r1Mul computes (2^128 - 1) * G without overflowing K_add kloBits", async () => {
    const scalar = LIMB_BASE - 1n;
    const expected = G.multiply(scalar).toAffine();
    const witness = await mulCircuit.calculateWitness({ scalar, xP: GX, yP: GY });
    await mulCircuit.expectConstraintPass(witness);
    const out = await mulCircuit.readWitness(witness, ["main.outX", "main.outY"]);
    assert.strictEqual(out["main.outX"], expected.x);
    assert.strictEqual(out["main.outY"], expected.y);
  });

  it("ECDSA accepts a FIPS 186-5 valid low-S signature with digest scalar m = 2^128 - 1", async () => {
    const d = 5n;
    const pub = G.multiply(d);
    const m = LIMB_BASE - 1n;

    let k = 7n;
    let R = G.multiply(k).toAffine();
    let r = modQ(R.x);
    let s = modQ(modInv(k, Q) * (m + r * d));
    if (s > Q / 2n) {
      k = Q - k;
      R = G.multiply(k).toAffine();
      r = modQ(R.x);
      s = modQ(modInv(k, Q) * (m + r * d));
    }
    const sInverse = modInv(s, Q);

    // Isolate strictly from FV-02 (s in {0, 1, q-2, q-1}), FV-03 (R.x >= q), and FV-09 on r/s_inverse
    assert.ok(s > 0n && s <= Q / 2n, "low-S");
    assert.ok(R.x < Q, "avoids FV-03 high-x");
    assert.ok(r >= Q - T_Q && r <= Q - 3n, "r outside FV-02 and FV-09 ranges");
    assert.ok(sInverse >= Q - T_Q && sInverse <= Q - 3n, "s_inverse outside FV-02 and FV-09 ranges");

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

import type { WitnessTester } from "circomkit";
import assert from "assert";
import { randomBytes } from "crypto";
import { circomkit } from "../common/index.ts";
import { witnessIndices } from "../common/witness-signals.ts";
import { bindPredicateName } from "../common/claim-identity.ts";
import { generateMockData } from "../../src/mock-vc-generator.ts";
import { generateShowCircuitParams, generateShowInputs, signDeviceNonce } from "../../src/show.ts";
import {
  buildRevocationWitness,
  bytesToBigInt,
  computeRevocationCommitment,
  createRevocationRegistry,
  generateRevocationValue,
  issuerKeyBits,
  toLimbs,
  type IssuerKeyPoint,
  type RevocationWitness,
} from "../../src/revocation.ts";
import { p256 } from "@noble/curves/nist.js";

const MAX_DEPTH = 4;

const ISSUER: IssuerKeyPoint = { x: p256.Point.BASE.x, y: p256.Point.BASE.y };
const OTHER_ISSUER: IssuerKeyPoint = (() => {
  const { x, y } = p256.Point.BASE.multiply(2n).toAffine();
  return { x, y };
})();
const randomCommitments = (n: number) => Array.from({ length: n }, () => bytesToBigInt(randomBytes(32)));

function checkInputs(w: RevocationWitness, issuer: IssuerKeyPoint = ISSUER) {
  return {
    issuerKeyBits: issuerKeyBits(issuer),
    value: w.revocationValue,
    leafValue: w.revocationLeafValue,
    leafNextValue: w.revocationLeafNextValue,
    leafIndex: w.revocationLeafIndex,
    depth: w.revocationDepth,
    siblings: w.revocationSiblings,
  };
}

// Reuses the Merkle path of a leaf `commitment` is a member of.
function withLeafOf(w: RevocationWitness, registry: ReturnType<typeof createRevocationRegistry>, commitment: bigint) {
  const proof = registry.generateProof(commitment);
  const siblings = Array.from({ length: MAX_DEPTH }, (_, i) => toLimbs(proof.siblings[i] ?? 0n));
  return {
    ...checkInputs(w),
    leafValue: toLimbs(proof.leaf.value),
    leafNextValue: toLimbs(proof.leaf.nextValue),
    leafIndex: BigInt(proof.leafIndex),
    depth: BigInt(proof.siblings.length),
    siblings,
  };
}

describe("RevocationCommitment", () => {
  let circuit: WitnessTester<["issuerKeyBits", "value"], ["out"]>;

  before(async () => {
    circuit = await circomkit.WitnessTester("RevocationCommitment", {
      file: "components/revocation",
      template: "RevocationCommitment",
      recompile: true,
    });
  });

  it("matches sha256(be32(x) || be32(y) || be32(value) || be32(3))", async () => {
    const value = generateRevocationValue();
    await circuit.expectPass(
      { issuerKeyBits: issuerKeyBits(ISSUER), value: toLimbs(value) },
      { out: toLimbs(computeRevocationCommitment(ISSUER, value)) },
    );
  });

  it("gives different commitments for the same value under different issuers", () => {
    const value = generateRevocationValue();
    assert.notStrictEqual(computeRevocationCommitment(ISSUER, value), computeRevocationCommitment(OTHER_ISSUER, value));
  });

  it("rejects a limb above 128 bits", async () => {
    await circuit.expectFail({ issuerKeyBits: issuerKeyBits(ISSUER), value: [1n << 128n, 0n] });
  });
});

describe("RevocationCheck", () => {
  let circuit: WitnessTester<any, ["root"]>;

  before(async () => {
    circuit = await circomkit.WitnessTester("RevocationCheck", {
      file: "components/revocation",
      template: "RevocationCheck",
      params: [MAX_DEPTH],
      recompile: true,
    });
  });

  it("proves an unrevoked credential and outputs the registry root", async () => {
    const registry = createRevocationRegistry(randomCommitments(7));
    const witness = buildRevocationWitness(ISSUER, generateRevocationValue(), registry, MAX_DEPTH);

    await circuit.expectPass(checkInputs(witness), { root: toLimbs(registry.root) });
  });

  it("outputs root 0 for an empty registry", async () => {
    const witness = buildRevocationWitness(ISSUER, generateRevocationValue(), createRevocationRegistry(), MAX_DEPTH);

    await circuit.expectPass(checkInputs(witness), { root: [0n, 0n] });
  });

  it("rejects a revoked commitment", async () => {
    const value = generateRevocationValue();
    const commitment = computeRevocationCommitment(ISSUER, value);
    const registry = createRevocationRegistry([...randomCommitments(3), commitment]);
    const witness = buildRevocationWitness(ISSUER, value, createRevocationRegistry(), MAX_DEPTH);

    await circuit.expectFail(withLeafOf(witness, registry, commitment));
  });

  it("does not revoke the same value under another issuer", async () => {
    const value = generateRevocationValue();
    const registry = createRevocationRegistry([...randomCommitments(3), computeRevocationCommitment(OTHER_ISSUER, value)]);
    const witness = buildRevocationWitness(ISSUER, value, registry, MAX_DEPTH);

    await circuit.expectPass(checkInputs(witness), { root: toLimbs(registry.root) });
    assert.throws(() => buildRevocationWitness(OTHER_ISSUER, value, registry, MAX_DEPTH), /revoked/);
  });

  it("rejects a witness built for another issuer's commitment", async () => {
    const value = generateRevocationValue();
    const commitment = computeRevocationCommitment(ISSUER, value);
    const registry = createRevocationRegistry([...randomCommitments(3), commitment]);
    // A non-membership path for (OTHER_ISSUER, value) does not cover (ISSUER, value).
    const witness = buildRevocationWitness(OTHER_ISSUER, value, registry, MAX_DEPTH);

    await circuit.expectFail(checkInputs(witness, ISSUER));
  });

  it("rejects a low leaf that does not bracket the commitment", async () => {
    const revoked = randomCommitments(7);
    const registry = createRevocationRegistry(revoked);
    const witness = buildRevocationWitness(ISSUER, generateRevocationValue(), registry, MAX_DEPTH);
    const lowLeaf = (witness.revocationLeafValue[0] << 128n) | witness.revocationLeafValue[1];
    const other = revoked.find((v) => v !== lowLeaf)!;

    await circuit.expectFail(withLeafOf(witness, registry, other));
  });

  it("outputs a different root for a tampered path", async () => {
    const registry = createRevocationRegistry(randomCommitments(7));
    const witness = buildRevocationWitness(ISSUER, generateRevocationValue(), registry, MAX_DEPTH);
    witness.revocationSiblings[0] = toLimbs(1n);

    const w = await circuit.calculateWitness(checkInputs(witness));
    const out = await circuit.readWitnessSignals(w, ["root"]);
    assert.notDeepStrictEqual(out.root, toLimbs(registry.root));
  });
});

describe("Show with revocation", () => {
  let circuit: WitnessTester<any, ["expressionResult", "revocationRoot"]>;

  before(async () => {
    circuit = await circomkit.WitnessTester("Show", {
      file: "show",
      template: "Show",
      params: [2, 2, 8, 64, MAX_DEPTH],
      recompile: true,
    });
  });

  it("outputs the revocation root", async () => {
    const mockData = await generateMockData({ circuitParams: [2048, 2000, 4, 50, 128] });
    const nonce = "revocation-show-nonce";
    const inputs = generateShowInputs(
      generateShowCircuitParams(mockData.circuitParams),
      nonce,
      signDeviceNonce(nonce, mockData.devicePrivateKey),
      mockData.deviceKey,
      [],
      [],
      [0n],
    );
    await bindPredicateName(inputs, 0, 0, "name");
    const registry = createRevocationRegistry(randomCommitments(5));
    const witness = buildRevocationWitness(ISSUER, mockData.revocationValue, registry, MAX_DEPTH);

    await circuit.expectPass({ ...inputs, ...witness }, { revocationRoot: toLimbs(registry.root) });
  });

  it("rejects a credential whose commitment under its issuer is revoked", async () => {
    const mockData = await generateMockData({ circuitParams: [2048, 2000, 4, 50, 128] });
    const nonce = "revocation-show-nonce";
    const inputs = generateShowInputs(
      generateShowCircuitParams(mockData.circuitParams),
      nonce,
      signDeviceNonce(nonce, mockData.devicePrivateKey),
      mockData.deviceKey,
      [],
      [],
      [0n],
    );
    await bindPredicateName(inputs, 0, 0, "name");
    const commitment = computeRevocationCommitment(ISSUER, mockData.revocationValue);
    const registry = createRevocationRegistry([...randomCommitments(4), commitment]);
    const witness = buildRevocationWitness(ISSUER, mockData.revocationValue, createRevocationRegistry(), MAX_DEPTH);

    // The membership path of the revoked commitment, under Show's input names.
    const proof = registry.generateProof(commitment);
    await circuit.expectFail({
      ...inputs,
      ...witness,
      revocationLeafValue: toLimbs(proof.leaf.value),
      revocationLeafNextValue: toLimbs(proof.leaf.nextValue),
      revocationLeafIndex: BigInt(proof.leafIndex),
      revocationDepth: BigInt(proof.siblings.length),
      revocationSiblings: Array.from({ length: MAX_DEPTH }, (_, i) => toLimbs(proof.siblings[i] ?? 0n)),
    });
  });
});

describe("JWT revocation value extraction", () => {
  const PARAMS = [2048, 2000, 4, 50, 128];
  let circuit: WitnessTester<any, any>;

  before(async () => {
    circuit = await circomkit.WitnessTester("JWT", {
      file: "jwt",
      template: "JWT",
      params: PARAMS,
      recompile: true,
    });
  });

  it("extracts the signed revocation value as [hi, lo] limbs", async () => {
    const mockData = await generateMockData({ circuitParams: PARAMS });
    const witness = await circuit.calculateWitness(mockData.circuitInputs);
    await circuit.expectConstraintPass(witness);

    const indices = await witnessIndices(circuit, ["main.RevocationValue[0]", "main.RevocationValue[1]"]);
    assert.deepStrictEqual(
      indices.map((i) => witness[i]),
      toLimbs(mockData.revocationValue),
    );
  });

  it("rejects an index that does not point at the anchor", async () => {
    const mockData = await generateMockData({ circuitParams: PARAMS });
    const inputs = { ...mockData.circuitInputs };
    inputs.revocationValueIndex += 1;

    await circuit.expectFail(inputs);
  });
});

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
  toLimbs,
  type RevocationWitness,
} from "../../src/revocation.ts";

const MAX_DEPTH = 4;

const newSecret = () => new Uint8Array(randomBytes(32));
const randomCommitments = (n: number) => Array.from({ length: n }, () => bytesToBigInt(randomBytes(32)));

function checkInputs(w: RevocationWitness) {
  return {
    secret: w.revocationSecret,
    commitment: w.revocationCommitment,
    leafValue: w.revocationLeafValue,
    leafNextValue: w.revocationLeafNextValue,
    leafIndex: w.revocationLeafIndex,
    depth: w.revocationDepth,
    siblings: w.revocationSiblings,
  };
}

// Reuses the Merkle path of a leaf `value` is a member of.
function withLeafOf(w: RevocationWitness, registry: ReturnType<typeof createRevocationRegistry>, value: bigint) {
  const proof = registry.generateProof(value);
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

  it("proves an unrevoked commitment and outputs the registry root", async () => {
    const registry = createRevocationRegistry(randomCommitments(7));
    const witness = buildRevocationWitness(newSecret(), registry, MAX_DEPTH);

    await circuit.expectPass(checkInputs(witness), { root: toLimbs(registry.root) });
  });

  it("outputs root 0 for an empty registry", async () => {
    const witness = buildRevocationWitness(newSecret(), createRevocationRegistry(), MAX_DEPTH);

    await circuit.expectPass(checkInputs(witness), { root: [0n, 0n] });
  });

  it("rejects a revoked commitment", async () => {
    const secret = newSecret();
    const commitment = computeRevocationCommitment(secret);
    const registry = createRevocationRegistry([...randomCommitments(3), commitment]);
    const witness = buildRevocationWitness(secret, createRevocationRegistry(), MAX_DEPTH);

    await circuit.expectFail(withLeafOf(witness, registry, commitment));
  });

  it("rejects a low leaf that does not bracket the commitment", async () => {
    const revoked = randomCommitments(7);
    const registry = createRevocationRegistry(revoked);
    const witness = buildRevocationWitness(newSecret(), registry, MAX_DEPTH);
    const lowLeaf = (witness.revocationLeafValue[0] << 128n) | witness.revocationLeafValue[1];
    const other = revoked.find((v) => v !== lowLeaf)!;

    await circuit.expectFail(withLeafOf(witness, registry, other));
  });

  it("rejects a secret that does not open the commitment", async () => {
    const registry = createRevocationRegistry(randomCommitments(3));
    const witness = buildRevocationWitness(newSecret(), registry, MAX_DEPTH);

    await circuit.expectFail({ ...checkInputs(witness), secret: toLimbs(bytesToBigInt(newSecret())) });
  });

  it("outputs a different root for a tampered path", async () => {
    const registry = createRevocationRegistry(randomCommitments(7));
    const witness = buildRevocationWitness(newSecret(), registry, MAX_DEPTH);
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
    const witness = buildRevocationWitness(mockData.revocationSecret, registry, MAX_DEPTH);

    await circuit.expectPass({ ...inputs, ...witness }, { revocationRoot: toLimbs(registry.root) });
  });
});

describe("JWT revocation commitment extraction", () => {
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

  it("extracts the signed commitment as [hi, lo] limbs", async () => {
    const mockData = await generateMockData({ circuitParams: PARAMS });
    const witness = await circuit.calculateWitness(mockData.circuitInputs);
    await circuit.expectConstraintPass(witness);

    const indices = await witnessIndices(circuit, ["main.RevocationCommitment[0]", "main.RevocationCommitment[1]"]);
    assert.deepStrictEqual(
      indices.map((i) => witness[i]),
      toLimbs(mockData.revocationCommitment),
    );
  });

  it("rejects an index that does not point at the anchor", async () => {
    const mockData = await generateMockData({ circuitParams: PARAMS });
    const inputs = { ...mockData.circuitInputs };
    inputs.revocationCommitmentIndex += 1;

    await circuit.expectFail(inputs);
  });
});

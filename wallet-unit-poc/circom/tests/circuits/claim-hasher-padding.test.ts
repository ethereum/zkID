import assert from "assert";
import { createHash } from "node:crypto";
import { circomkit } from "../common/index.ts";
import { encodeClaims } from "../../src/utils.ts";

describe("ClaimHasher disclosure padding", () => {
  const disclosures = ["Alicia", "Cameron"].map((name) =>
    Buffer.from(JSON.stringify(["padding-fixture", "given_name", name])).toString("base64url"),
  );
  const referenceDigests = disclosures.map((disclosure) =>
    Array.from(createHash("sha256").update(disclosure, "ascii").digest(), BigInt),
  );

  let hashes: bigint[][];

  before(async () => {
    // The SHA-256 marker and eight-byte length fit in one block at 55 bytes.
    // At 56 bytes, the same padding rule needs two blocks.
    assert.deepStrictEqual(disclosures.map((disclosure) => Buffer.byteLength(disclosure)), [55, 56]);
    const { claimArray } = encodeClaims(disclosures, 2, 128);
    assert.deepStrictEqual(claimArray[0].slice(64), Array<bigint>(64).fill(0n));

    const circuit = await circomkit.WitnessTester("ClaimHasherPadding128", {
      file: "components/claim-decoder",
      template: "ClaimHasher",
      params: [2, 128],
      recompile: true,
    });
    const witness = await circuit.calculateWitness({ claims: claimArray });
    await circuit.expectConstraintPass(witness);
    hashes = (await circuit.readWitnessSignals(witness, ["claimHashes"])).claimHashes as bigint[][];
  });

  it("matches SHA-256 for a one-block disclosure in the 128-byte buffer", () => {
    assert.strictEqual(hashes[0].length, 32);
    assert.deepStrictEqual(hashes[0], referenceDigests[0], "55-byte disclosure digest must match Node SHA-256");
  });

  it("matches SHA-256 when the disclosure uses two padded blocks", () => {
    assert.deepStrictEqual(hashes[1], referenceDigests[1]);
  });

  it("matches SHA-256 for the same short disclosure with a one-block hasher", async () => {
    const { claimArray } = encodeClaims([disclosures[0]], 1, 64);
    const circuit = await circomkit.WitnessTester("ClaimHasherPadding64", {
      file: "components/claim-decoder",
      template: "ClaimHasher",
      params: [1, 64],
      recompile: true,
    });
    const witness = await circuit.calculateWitness({ claims: claimArray });
    await circuit.expectConstraintPass(witness);
    const { claimHashes } = await circuit.readWitnessSignals(witness, ["claimHashes"]);
    assert.deepStrictEqual(claimHashes, [referenceDigests[0]]);
  });
});

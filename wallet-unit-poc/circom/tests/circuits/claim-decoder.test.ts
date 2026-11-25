import { sha256 } from "@noble/hashes/sha2";
import assert from "assert";
import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";
import { base64urlToBase64, encodeClaims } from "../../src/utils.ts";
import { generateMockData } from "../../src/mock-vc-generator.ts";

describe("ClaimDecoder", () => {
  let circuit: WitnessTester<["claims", "claimLengths", "decodeFlags"], ["decodedClaims"]>;

  const maxClaimsLength = 128;
  const maxClaims = 3;

  before(async () => {
    circuit = await circomkit.WitnessTester("ClaimDecoder", {
      file: "components/claim-decoder",
      template: "ClaimDecoder",
      params: [maxClaims, maxClaimsLength],
      recompile: true,
    });
  });

  it("Decode Raw claim testcase-1", async () => {
    const inputs = [
      "WyJ1cWJ5Y0VSZlN4RXF1a0dtWGwyXzl3IiwibmFtZSIsImRlbmtlbmkiXQ",
      "WyJYMXllNDloV0s1bTJneWFBLXROQXRnIiwicm9jX2JpcnRoZGF5IiwiMDc1MDEwMSJd",
    ];
    const expectedOutputs = inputs.map(atob);
    const { claimArray, claimLengths } = encodeClaims(inputs, maxClaims, maxClaimsLength);

    const decodeFlags = [1, 1, 1];
    const witness = await circuit.calculateWitness({
      claims: claimArray,
      claimLengths,
      decodeFlags,
    });

    const outputs = await circuit.readWitnessSignals(witness, ["decodedClaims"]);

    const decodedClaims = outputs.decodedClaims as number[][];

    for (let i = 0; i < inputs.length; i++) {
      let length = Number(claimLengths[i]);
      const base64 = decodedClaims[i]
        .slice(0, length)
        .map((c) => String.fromCharCode(Number(c)))
        .join("")
        .replace(/[\x00-\x1F]+$/g, "");

      assert.strictEqual(base64, expectedOutputs[i]);
    }
    await circuit.expectConstraintPass(witness);
  });

  it("Decode Raw claim testcase-2", async () => {
    const testcase = [
      "WyJmSGlPTE9ZRVFhZkF3MjBCZjRxZXpBIiwibmFtZSIsIumZs-etseeOsiJd",
      "WyJLVXYxVF9BNXpvVDlJbXFURmUwdUxnIiwiaWRfbnVtYmVyIiwiQTIzNDU2Nzg5MCJd",
      "WyJuTDVDa2VaV2paSG13UjcxV05lWlZ3Iiwicm9jX2JpcnRoZGF5IiwiMDU3MDYwNSJd",
      "WyJvZFNweWFjaUNuZUJneld1VEFyM0pRIiwidHlwZSIsIuaZrumAmuWwj-Wei-i7iiJd",
      "WyJJdFVGQUV2S0kybFJCV2MzU19LTjhnIiwiY29udHJvbG51bWJlciIsIjQwMTA0MDIwOTE0NDUiXQ",
      "WyJROWEySWM3b1IxUjRFQ0VXX3RYaUlRIiwiZ0RhdGUiLCIxMDIwNzAxIl0",
    ];

    const maxClaimsLength = 128;
    const maxClaims = 8;

    circuit = await circomkit.WitnessTester("ClaimDecoder", {
      file: "components/claim-decoder",
      template: "ClaimDecoder",
      params: [maxClaims, maxClaimsLength],
      recompile: true,
    });

    const decodeFlags = [0, 0, 1, 0, 0, 0, 0, 0];

    const expectedOutputs = testcase.map((s) => atob(base64urlToBase64(s)));
    const { claimArray, claimLengths } = encodeClaims(testcase, maxClaims, maxClaimsLength);

    const inputs = {
      claims: claimArray,
      claimLengths,
      decodeFlags,
    };
    const witness = await circuit.calculateWitness(inputs);
    const outputs = await circuit.readWitnessSignals(witness, ["decodedClaims"]);

    const decodedClaims = outputs.decodedClaims as number[][];

    for (let i = 0; i < testcase.length; i++) {
      const length = Number(claimLengths[i]);
      const base64 = decodedClaims[i]
        .slice(0, length)
        .map((c) => String.fromCharCode(Number(c)))
        .join("")
        .replace(/[\x00-\x1F]+$/g, "");

      if (decodeFlags[i] === 1) {
        assert.strictEqual(base64, expectedOutputs[i]);
      } else {
        assert.strictEqual(base64, "");
      }
    }

    await circuit.expectConstraintPass(witness);
  });

  it("Decode Raw claim testcase-3", async () => {
    let mockdata = await generateMockData({
      claims: [
        { key: "name", value: "John Doe" },
        { key: "roc_birthday", value: "1040605" },
        { key: "email", value: "john.doe@example.com" },
      ],
    });

    let claims = mockdata.circuitInputs.claims;
    let claimLengths = mockdata.circuitInputs.claimLengths;
    let decodeFlags = mockdata.circuitInputs.decodeFlags;

    let claimString: string[] = claims.map((c: bigint[], i: number) => {
      const length = Number(claimLengths[i]);
      if (length === 0) return "";
      const bytesArray = c.slice(0, length).map((b: bigint) => Number(b));
      return Buffer.from(bytesArray).toString("utf8");
    });

    const expectedOutputs = claimString.map((s) => atob(base64urlToBase64(s)));

    circuit = await circomkit.WitnessTester("ClaimDecoder", {
      file: "components/claim-decoder",
      template: "ClaimDecoder",
      params: [mockdata.circuitParams.maxMatches - 2, mockdata.circuitParams.maxClaimLength],
      recompile: true,
    });

    const witness = await circuit.calculateWitness({
      claims: claims,
      claimLengths: claimLengths,
      decodeFlags: decodeFlags,
    });

    await circuit.expectConstraintPass(witness);

    const outputs = await circuit.readWitnessSignals(witness, ["decodedClaims"]);
    const decodedClaims = outputs.decodedClaims as number[][];

    for (let i = 0; i < claimString.length; i++) {
      const length = Number(claimLengths[i]);
      const base64 = decodedClaims[i]
        .slice(0, length)
        .map((c) => String.fromCharCode(Number(c)))
        .join("")
        .replace(/[\x00-\x1F]+$/g, "");

      if (decodeFlags[i] === 1) {
        assert.strictEqual(base64, expectedOutputs[i]);
      } else {
        assert.strictEqual(base64, "");
      }
    }
  });
});

describe("ClaimHasher", () => {
  let circuit: WitnessTester<["claims", "claimLengths"], ["claimHashes"]>;

  const maxClaimsLength = 128;
  const maxClaims = 3;

  before(async () => {
    circuit = await circomkit.WitnessTester("ClaimDecoder", {
      file: "components/claim-decoder",
      template: "ClaimHasher",
      params: [maxClaims, maxClaimsLength],
      recompile: true,
    });
  });

  it("sha256 of rawclaims testcase-1", async () => {
    const inputs = [
      "WyJ1cWJ5Y0VSZlN4RXF1a0dtWGwyXzl3IiwibmFtZSIsImRlbmtlbmkiXQ",
      "WyJYMXllNDloV0s1bTJneWFBLXROQXRnIiwicm9jX2JpcnRoZGF5IiwiMDc1MDEwMSJd",
    ];
    const { claimArray, claimLengths } = encodeClaims(inputs, maxClaims, maxClaimsLength);

    const witness = await circuit.calculateWitness({
      claims: claimArray,
      claimLengths,
    });

    await circuit.expectConstraintPass(witness);

    const outputs = await circuit.readWitnessSignals(witness, ["claimHashes"]);
    const circuitClaimHash = outputs.claimHashes as number[][];

    for (let i = 0; i < inputs.length; i++) {
      const length = Number(claimLengths[i]);
      const expectedHash = sha256(Uint8Array.from(Buffer.from(inputs[i].slice(0, length), "utf8")));
      const expectedHashHex = Array.from(expectedHash, (b) => b.toString(16).padStart(2, "0")).join("");
      const circuitHashHex = circuitClaimHash[i].map((b) => b.toString(16).padStart(2, "0")).join("");
      assert.strictEqual(circuitHashHex, expectedHashHex);
    }
  });

  it("rejects a decode length shorter than the authenticated disclosure", async () => {
    const { claimArray, claimLengths } = encodeClaims(["A".repeat(64)], maxClaims, maxClaimsLength);
    claimLengths[0] = 60n;
    await assert.rejects(
      () => circuit.calculateWitness({ claims: claimArray, claimLengths }),
      /Assert Failed/,
    );
  });

  it("rejects a changed SHA marker, zero padding, trailer, or out-of-range length", async () => {
    const encoded = encodeClaims(["A".repeat(56)], maxClaims, maxClaimsLength);
    encoded.claimArray[0]![56] = 0n;
    await assert.rejects(
      () => circuit.calculateWitness({ claims: encoded.claimArray, claimLengths: encoded.claimLengths }),
      /Assert Failed/,
    );

    const changedZeroPadding = encodeClaims(["A".repeat(56)], maxClaims, maxClaimsLength);
    changedZeroPadding.claimArray[0]![57] = 7n;
    await assert.rejects(
      () => circuit.calculateWitness({ claims: changedZeroPadding.claimArray, claimLengths: changedZeroPadding.claimLengths }),
      /Assert Failed/,
    );

    const changedOneBlockPadding = encodeClaims(["A".repeat(50)], maxClaims, maxClaimsLength);
    changedOneBlockPadding.claimArray[0]![51] = 7n;
    await assert.rejects(
      () => circuit.calculateWitness({ claims: changedOneBlockPadding.claimArray, claimLengths: changedOneBlockPadding.claimLengths }),
      /Assert Failed/,
    );

    const changedTrailer = encodeClaims(["A".repeat(56)], maxClaims, maxClaimsLength);
    changedTrailer.claimArray[0]![127] = 0n;
    await assert.rejects(
      () => circuit.calculateWitness({ claims: changedTrailer.claimArray, claimLengths: changedTrailer.claimLengths }),
      /Assert Failed/,
    );

    const overlong = encodeClaims(["A".repeat(119)], maxClaims, maxClaimsLength);
    overlong.claimLengths[0] = 120n;
    await assert.rejects(
      () => circuit.calculateWitness({ claims: overlong.claimArray, claimLengths: overlong.claimLengths }),
      /Assert Failed/,
    );
  });

  it("hashes correctly across the one-block/two-block boundary", async () => {
    const inputs = ["A".repeat(55), "A".repeat(56), "A".repeat(119)];
    const { claimArray, claimLengths } = encodeClaims(inputs, maxClaims, maxClaimsLength);
    const witness = await circuit.calculateWitness({ claims: claimArray, claimLengths });
    await circuit.expectConstraintPass(witness);
    const { claimHashes } = await circuit.readWitnessSignals(witness, ["claimHashes"]);
    for (let i = 0; i < inputs.length; i++) {
      assert.deepStrictEqual(
        (claimHashes as bigint[][])[i]!.map(Number),
        Array.from(sha256(Buffer.from(inputs[i]!))),
      );
    }
  });

  it("sha256 of rawclaims testcase-2", async () => {
    const testcase = [
      "WyJmSGlPTE9ZRVFhZkF3MjBCZjRxZXpBIiwibmFtZSIsIumZs-etseeOsiJd",
      "WyJLVXYxVF9BNXpvVDlJbXFURmUwdUxnIiwiaWRfbnVtYmVyIiwiQTIzNDU2Nzg5MCJd",
      "WyJuTDVDa2VaV2paSG13UjcxV05lWlZ3Iiwicm9jX2JpcnRoZGF5IiwiMDU3MDYwNSJd",
      "WyJvZFNweWFjaUNuZUJneld1VEFyM0pRIiwidHlwZSIsIuaZrumAmuWwj-Wei-i7iiJd",
      "WyJJdFVGQUV2S0kybFJCV2MzU19LTjhnIiwiY29udHJvbG51bWJlciIsIjQwMTA0MDIwOTE0NDUiXQ",
      "WyJROWEySWM3b1IxUjRFQ0VXX3RYaUlRIiwiZ0RhdGUiLCIxMDIwNzAxIl0",
    ];

    const maxClaimsLength = 128;
    const maxClaims = 8;

    circuit = await circomkit.WitnessTester("ClaimDecoder", {
      file: "components/claim-decoder",
      template: "ClaimHasher",
      params: [maxClaims, maxClaimsLength],
      recompile: true,
    });

    const { claimArray, claimLengths } = encodeClaims(testcase, maxClaims, maxClaimsLength);

    const witness = await circuit.calculateWitness({ claims: claimArray, claimLengths });
    const outputs = await circuit.readWitnessSignals(witness, ["claimHashes"]);

    const circuitClaimHash = outputs.claimHashes as number[][];

    for (let i = 0; i < testcase.length; i++) {
      const length = Number(claimLengths[i]);
      const expectedHash = sha256(Uint8Array.from(Buffer.from(testcase[i].slice(0, length), "utf8")));
      const expectedHashHex = Array.from(expectedHash, (b) => b.toString(16).padStart(2, "0")).join("");
      const circuitHashHex = circuitClaimHash[i].map((b) => b.toString(16).padStart(2, "0")).join("");
      assert.strictEqual(circuitHashHex, expectedHashHex);
    }

    await circuit.expectConstraintPass(witness);
  });

  it("sha256 of rawclaims testcase-3", async () => {
    let mockdata = await generateMockData({
      claims: [
        { key: "name", value: "John Doe" },
        { key: "roc_birthday", value: "1040605" },
        { key: "email", value: "john.doe@example.com" },
      ],
    });

    const maxClaimsLength = mockdata.circuitParams.maxClaimLength;
    const maxClaims = mockdata.circuitParams.maxMatches - 2;

    circuit = await circomkit.WitnessTester("ClaimDecoder", {
      file: "components/claim-decoder",
      template: "ClaimHasher",
      params: [maxClaims, maxClaimsLength],
      recompile: true,
    });

    const claimArray = mockdata.circuitInputs.claims;
    const claimLengths = mockdata.circuitInputs.claimLengths;

    let claimString: string[] = claimArray.map((c: bigint[], i: number) => {
      const length = Number(claimLengths[i]);
      if (length === 0) return "";
      const bytesArray = c.slice(0, length).map((b: bigint) => Number(b));
      return Buffer.from(bytesArray).toString("utf8");
    });

    const witness = await circuit.calculateWitness({ claims: claimArray, claimLengths });
    await circuit.expectConstraintPass(witness);

    const outputs = await circuit.readWitnessSignals(witness, ["claimHashes"]);
    const circuitClaimHash = outputs.claimHashes as number[][];

    for (let i = 0; i < claimString.length; i++) {
      if (claimString[i] !== "") {
        const expectedHash = sha256(Uint8Array.from(Buffer.from(claimString[i], "utf8")));
        let expectedHashHex: string = Array.from(expectedHash, (b) => b.toString(16).padStart(2, "0")).join("");
        let circuitHash: string = circuitClaimHash[i].map((b) => b.toString(16).padStart(2, "0")).join("");
        assert.strictEqual(circuitHash, expectedHashHex);
      }
    }
  });
});

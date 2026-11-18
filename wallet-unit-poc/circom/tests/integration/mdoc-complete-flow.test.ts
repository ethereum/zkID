import { strict as assert } from "assert";
import type { WitnessTester } from "circomkit";
import { p256 } from "@noble/curves/nist.js";
import { circomkit } from "../common/index.ts";
import { buildMdocWitness, MDOC_PARAMS, packString, ymdToYyyymmdd } from "../common/mdoc-fixture.ts";
import { createTestMdocCredential } from "../../src/mdoc-fixture.ts";
import { generateMdocCircuitParams, generateMdocInputs, parseMdocClaims } from "../../src/mdoc.ts";
import { generateShowInputs, signDeviceNonce } from "../../src/show.ts";
import { bindPredicateName, hashClaimName } from "../common/claim-identity.ts";
import { witnessIndices } from "../common/witness-signals.ts";

const SHOW_PARAMS = [2, 2, 8, 64] as const;
const SHOW_PARAM_OBJ = {
  nClaims: SHOW_PARAMS[0],
  maxPredicates: SHOW_PARAMS[1],
  maxLogicTokens: SHOW_PARAMS[2],
  valueBits: SHOW_PARAMS[3],
};

type ShowInputs = ReturnType<typeof generateShowInputs>;

interface PredicateSpec {
  claimRef: bigint;
  op: bigint; // 0=LE, 1=GE, 2=EQ
  rhs: bigint;
}

function devicePubKeyJwk(x: Uint8Array, y: Uint8Array) {
  return {
    kty: "EC",
    crv: "P-256",
    x: Buffer.from(x).toString("base64url"),
    y: Buffer.from(y).toString("base64url"),
  };
}

function setSinglePredicate(inputs: ShowInputs, { claimRef, op, rhs }: PredicateSpec): void {
  inputs.predicateLen = 1n;
  inputs.predicateClaimRefs[0] = claimRef;
  inputs.predicateOps[0] = op;
  inputs.predicateRhsValues[0] = rhs;
  inputs.tokenTypes[0] = 0n; // REF to predicate 0
  inputs.tokenValues[0] = 0n;
  inputs.exprLen = 1n;
}

describe("Complete Flow: Register (MDOC) → Show Circuit", () => {
  let mdocCircuit: WitnessTester<any, any>;
  let showCircuit: WitnessTester<any, any>;

  before(async () => {
    mdocCircuit = await circomkit.WitnessTester("MDOC", {
      file: "mdoc",
      template: "MDOC",
      params: [...MDOC_PARAMS],
      recompile: true,
    });
    console.log("MDOC Circuit #constraints:", await mdocCircuit.getConstraintCount());

    showCircuit = await circomkit.WitnessTester("Show", {
      file: "show",
      template: "Show",
      params: [...SHOW_PARAMS],
      recompile: true,
    });
    console.log("Show Circuit #constraints:", await showCircuit.getConstraintCount());
  });

  it("passes the full flow: mdoc → normalized claims → Show predicate = true", async () => {
    const claimConfig = {
      birth_date: { type: "date" as const },
      resident_state: { type: "string" as const },
    };
    const { cred, inputs: mdocInputs } = await buildMdocWitness(claimConfig);

    const mdocWitness = await mdocCircuit.calculateWitness(mdocInputs);
    await mdocCircuit.expectConstraintPass(mdocWitness);

    const normalizedClaimValues = [ymdToYyyymmdd(cred.claims.birth_date), packString(cred.claims.resident_state)];

    const verifierNonce = "mdoc-flow-predicate-check";
    const showInputs = generateShowInputs(
      SHOW_PARAM_OBJ,
      verifierNonce,
      signDeviceNonce(verifierNonce, cred.devPrvHex),
      devicePubKeyJwk(cred.deviceKeyX, cred.deviceKeyY),
      [],
      [],
      normalizedClaimValues,
    );

    // born on or before 2000-01-01 (YYYYMMDD 20000101)
    setSinglePredicate(showInputs, { claimRef: 0n, op: 0n, rhs: 20000101n });
    await bindPredicateName(showInputs, 0, 0, "birth_date");

    await showCircuit.expectPass(showInputs, { expressionResult: 1n });
  });

  it("mdoc's claimIdentifierHashes match H(name) as Show derives it", async () => {
    const claimConfig = {
      birth_date: { type: "date" as const },
      resident_state: { type: "string" as const },
    };
    const { inputs: mdocInputs } = await buildMdocWitness(claimConfig);

    const mdocWitness = await mdocCircuit.calculateWitness(mdocInputs);
    await mdocCircuit.expectConstraintPass(mdocWitness);

    const [birthDateIdx, residentStateIdx] = await witnessIndices(mdocCircuit, [
      "main.claimIdentifierHashes[0]",
      "main.claimIdentifierHashes[1]",
    ]);

    assert.equal(mdocWitness[birthDateIdx], await hashClaimName("birth_date"));
    assert.equal(mdocWitness[residentStateIdx], await hashClaimName("resident_state"));
  });

  it("evaluates expressionResult=0 when the predicate is false", async () => {
    const claimConfig = {
      birth_date: { type: "date" as const },
      resident_state: { type: "string" as const },
    };
    const { cred, inputs: mdocInputs } = await buildMdocWitness(claimConfig);

    const mdocWitness = await mdocCircuit.calculateWitness(mdocInputs);
    await mdocCircuit.expectConstraintPass(mdocWitness);

    const normalizedClaimValues = [ymdToYyyymmdd(cred.claims.birth_date), packString(cred.claims.resident_state)];
    const birthDate = normalizedClaimValues[0];

    const verifierNonce = "mdoc-flow-false-predicate";
    const showInputs = generateShowInputs(
      SHOW_PARAM_OBJ,
      verifierNonce,
      signDeviceNonce(verifierNonce, cred.devPrvHex),
      devicePubKeyJwk(cred.deviceKeyX, cred.deviceKeyY),
      [],
      [],
      normalizedClaimValues,
    );

    // force a false condition: birthDate <= (birthDate - 1)
    setSinglePredicate(showInputs, { claimRef: 0n, op: 0n, rhs: birthDate - 1n });
    await bindPredicateName(showInputs, 0, 0, "birth_date");

    await showCircuit.expectPass(showInputs, { expressionResult: 0n });
  });

  it("rejects a Show proof signed with a key other than the mdoc deviceKey", async () => {
    const cred = await createTestMdocCredential();
    const wrongKey = p256.utils.randomPrivateKey();
    const verifierNonce = "wrong-key-test";

    assert.throws(
      () =>
        generateShowInputs(
          SHOW_PARAM_OBJ,
          verifierNonce,
          signDeviceNonce(verifierNonce, Buffer.from(wrongKey).toString("hex")),
          devicePubKeyJwk(cred.deviceKeyX, cred.deviceKeyY),
          [],
          [],
          [0n, 0n],
        ),
      /Device signature verification failed/,
    );
  });

  it("rejects a tampered issuer-signed preimage in the mdoc circuit inputs", async () => {
    const cred = await createTestMdocCredential();
    const params = generateMdocCircuitParams([...MDOC_PARAMS]);
    const { claims, deviceKeyPos } = parseMdocClaims(cred.tbsData, cred.items, cred.deviceKeyX, {
      birth_date: { type: "date" },
    });

    const tampered = claims.map((c) => ({ ...c, preimage: new Uint8Array(c.preimage) }));
    tampered[0].preimage[5] ^= 0xff;

    assert.throws(
      () => generateMdocInputs(params, cred.tbsData, cred.signature, cred.issuerPubRaw, tampered, deviceKeyPos),
      /encoded digest.*not found/,
    );
  });
});

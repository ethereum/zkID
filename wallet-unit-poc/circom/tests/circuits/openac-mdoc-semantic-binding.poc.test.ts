import { strict as assert } from "assert";
import { sha256Pad } from "@zk-email/helpers";
import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";
import { MDOC_PARAMS, ymdToYyyymmdd } from "../common/mdoc-fixture.ts";
import { createTestMdocCredential } from "../../src/mdoc-fixture.ts";
import { generateMdocCircuitParams, generateMdocInputs, parseMdocClaims } from "../../src/mdoc.ts";
import { generateShowInputs, signDeviceNonce } from "../../src/show.ts";
import { bindPredicateName, hashClaimName } from "../common/claim-identity.ts";
import { uint8ArrayToBigIntArray } from "../../src/utils.ts";

const SHOW_PARAMS = [2, 2, 8, 64, 0] as const;
const SHOW_PARAM_OBJ = {
  nClaims: SHOW_PARAMS[0],
  maxPredicates: SHOW_PARAMS[1],
  maxLogicTokens: SHOW_PARAMS[2],
  valueBits: SHOW_PARAMS[3],
};

type MdocInputs = ReturnType<typeof generateMdocInputs>;
type ShowInputs = ReturnType<typeof generateShowInputs>;

function cloneInputs<T>(value: T): T {
  return structuredClone(value);
}

function devicePubKeyJwk(x: Uint8Array, y: Uint8Array) {
  return {
    kty: "EC",
    crv: "P-256",
    x: Buffer.from(x).toString("base64url"),
    y: Buffer.from(y).toString("base64url"),
  };
}

function setSingleLePredicate(inputs: ShowInputs, rhs: bigint): void {
  inputs.predicateLen = 1n;
  inputs.predicateClaimRefs[0] = 0n;
  inputs.predicateOps[0] = 0n; // <=
  inputs.predicateRhsIsRef[0] = 0n;
  inputs.predicateRhsValues[0] = rhs;
  inputs.tokenTypes[0] = 0n; // REF(predicate 0)
  inputs.tokenValues[0] = 0n;
  inputs.exprLen = 1n;
}

async function assertMdocProves(circuit: WitnessTester<any, any>, inputs: MdocInputs): Promise<void> {
  const witness = await circuit.calculateWitness(inputs);
  await circuit.expectConstraintPass(witness);
}

// normalizedClaimValues is an internal signal now, and the MDOC .sym file is too
// large for circomkit's symbol reader, so assert the expected normalization is
// present in the raw witness rather than indexing into it. A witness index would
// silently drift with the output layout, which is how this helper broke before.
async function assertMdocNormalizes(
  circuit: WitnessTester<any, any>,
  inputs: MdocInputs,
  expected: bigint,
): Promise<void> {
  const witness = await circuit.calculateWitness(inputs);
  await circuit.expectConstraintPass(witness);
  assert.ok(
    witness.some((w) => w === expected),
    `witness should contain normalized value ${expected}`,
  );
}

function buildShowInputs(
  cred: Awaited<ReturnType<typeof createTestMdocCredential>>,
  nonce: string,
  normalizedClaimValues: bigint[],
  claimIdentifierHashes: bigint[] = [],
): ShowInputs {
  return generateShowInputs(
    SHOW_PARAM_OBJ,
    nonce,
    signDeviceNonce(nonce, cred.devPrvHex),
    devicePubKeyJwk(cred.deviceKeyX, cred.deviceKeyY),
    [],
    [],
    normalizedClaimValues,
    claimIdentifierHashes,
  );
}

describe("OpenAC mdoc semantic binding PoC", () => {
  let mdocCircuit: WitnessTester<any, any>;
  let showCircuit: WitnessTester<any, any>;

  before(async () => {
    mdocCircuit = await circomkit.WitnessTester("MDOC", {
      file: "mdoc",
      template: "MDOC",
      params: [...MDOC_PARAMS],
      recompile: true,
    });

    showCircuit = await circomkit.WitnessTester("Show", {
      file: "show",
      template: "Show",
      params: [...SHOW_PARAMS],
      recompile: true,
    });
  });

  it("rejects reveal_digest bytes that are not the signed element value slice", async () => {
    const cred = await createTestMdocCredential();
    const params = generateMdocCircuitParams([...MDOC_PARAMS]);
    const { claims, deviceKeyPos } = parseMdocClaims(cred.tbsData, cred.items, cred.deviceKeyX, {
      family_name: { type: "reveal_digest" },
    });
    assert.equal(claims.length, 1, "fixture should contain family_name");

    const honest = generateMdocInputs(
      params,
      cred.tbsData,
      cred.signature,
      cred.issuerPubRaw,
      claims,
      deviceKeyPos,
    );
    await assertMdocProves(mdocCircuit, honest);

    const preimageTamper = cloneInputs(honest);
    const idByte = Number(preimageTamper.identifierPositions[0]) + 1;
    preimageTamper.preimages[0][idByte] = preimageTamper.preimages[0][idByte] ^ 1n;
    await mdocCircuit.expectFail(preimageTamper);

    const tampered = cloneInputs(honest);
    const attackerBytes = Uint8Array.from(Buffer.from("attacker-controlled reveal digest preimage", "utf8"));
    const [padded, paddedLen] = sha256Pad(attackerBytes, params.maxValueLen);
    tampered.digestInputsPadded[0] = uint8ArrayToBigIntArray(padded);
    tampered.digestInputsPaddedLen[0] = BigInt(paddedLen);

    // digestInputsPadded[0] is no longer the signed elementValue slice from
    // preimages[0]. The current circuit accepts it as an independent digest
    // preimage.
    await mdocCircuit.expectFail(tampered);
  });

  it("rejects using issue_date as the predicate slot for requested birth_date", async () => {
    const verifierCutoff = 20000101n;
    const cred = await createTestMdocCredential({
      birth_date: "2015-01-01",
      issue_date: "1990-01-01",
    });
    const params = generateMdocCircuitParams([...MDOC_PARAMS]);

    const issueParsed = parseMdocClaims(cred.tbsData, cred.items, cred.deviceKeyX, {
      issue_date: { type: "date" },
    });
    assert.equal(issueParsed.claims.length, 1, "fixture should contain issue_date");
    const issueInputs = generateMdocInputs(
      params,
      cred.tbsData,
      cred.signature,
      cred.issuerPubRaw,
      issueParsed.claims,
      issueParsed.deviceKeyPos,
    );
    const issueValue = ymdToYyyymmdd("1990-01-01");
    await assertMdocNormalizes(mdocCircuit, issueInputs, issueValue);

    const birthParsed = parseMdocClaims(cred.tbsData, cred.items, cred.deviceKeyX, {
      birth_date: { type: "date" },
    });
    assert.equal(birthParsed.claims.length, 1, "fixture should contain birth_date");
    const birthInputs = generateMdocInputs(
      params,
      cred.tbsData,
      cred.signature,
      cred.issuerPubRaw,
      birthParsed.claims,
      birthParsed.deviceKeyPos,
    );
    const birthValue = ymdToYyyymmdd("2015-01-01");
    await assertMdocNormalizes(mdocCircuit, birthInputs, birthValue);

    // Show hashes the policy's attribute name in-circuit; the slot identity is
    // the same H(name) on the credential side, bound to the slot by the fold's
    // shared segment.
    const ISSUE_ID = await hashClaimName("issue_date");

    const honestShow = buildShowInputs(cred, "mdoc-honest-birth-date-slot", [birthValue, 0n]);
    setSingleLePredicate(honestShow, verifierCutoff);
    await bindPredicateName(honestShow, 0, 0, "birth_date");
    await showCircuit.expectPass(honestShow, { expressionResult: 0n });

    const wrongIdentifier = cloneInputs(issueInputs);
    wrongIdentifier.identifierCbor[0][1] = wrongIdentifier.identifierCbor[0][1] ^ 1n;
    await mdocCircuit.expectFail(wrongIdentifier);

    // Slot 0 holds issue_date but the policy names birth_date. This used to
    // return expressionResult=1 and satisfy an age policy the credential fails.
    const maliciousShow = buildShowInputs(cred, "mdoc-wrong-identifier-slot", [issueValue, 0n]);
    setSingleLePredicate(maliciousShow, verifierCutoff);
    await bindPredicateName(maliciousShow, 0, 0, "birth_date");
    maliciousShow.claimIdentifierHashes[0] = ISSUE_ID;
    await showCircuit.expectFail(maliciousShow);
  });
});

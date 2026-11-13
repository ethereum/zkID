// Writes the mobile Flow fixtures deterministically, using the same input builders as precompute() and present().
// Usage: tsx scripts/gen-mobile-fixtures.ts --circom-build <dir> --out <flutter assets dir>

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { execFileSync } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { p256 } from "@noble/curves/nist.js";

import { Credential } from "../src/credential.js";
import { buildJwtCircuitInputs } from "../src/inputs/jwt-input-builder.js";
import {
  buildShowCircuitInputs,
  signDeviceNonce,
} from "../src/inputs/show-input-builder.js";
import { buildShowStatementPublicValues } from "../src/inputs/show-statement.js";
import {
  compilePredicateExpression,
  requiredNormalization,
  assertNormalizationSupports,
  type PredicateExpression,
} from "../src/predicates.js";
import {
  CLAIM_IDENTITY_WITNESS_START,
  CLAIM_VALUES_WITNESS_START,
  JWT_PARAMS_BY_SIZE,
  selectVcSizeForSigningInput,
} from "../src/sizing.js";
import { DEFAULT_SHOW_PARAMS, type EcdsaPublicKey } from "../src/types.js";
import { base64urlEncode, circuitInputsToJson } from "../src/utils.js";
import { WitnessCalculator } from "../src/witness-calculator.js";
import { generateDummyCredential } from "../src/testing/dummy-credential.js";

const SIZE = "2k" as const;
const ISSUER_URL = "https://issuer.example/";
// 2026-01-01 and 2030-01-01 UTC.
const NBF = 1767225600;
const EXP = 1893456000;
// The verifier clock for ageing; also the reference date in the policy text.
const NOW = Date.UTC(2026, 10, 12) / 1000;
const OTHER_ISSUER_PRIVATE_KEY =
  "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

const SDK_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

interface RequestDef {
  id: string;
  verifier: string;
  title: string;
  policyText: string;
  nonce: string;
  policy: PredicateExpression;
  // Issuer the verifier trusts; the credential's real issuer unless overridden.
  trustedIssuerKey?: EcdsaPublicKey;
}

function parseArgs(): { circomBuild: string; out: string } {
  const argv = process.argv.slice(2);
  const get = (flag: string): string => {
    const i = argv.indexOf(flag);
    const v = i >= 0 ? argv[i + 1] : undefined;
    if (!v) throw new Error(`missing ${flag}`);
    return resolve(v);
  };
  return { circomBuild: get("--circom-build"), out: get("--out") };
}

function sha256File(path: string): Promise<string> {
  return new Promise((res, rej) => {
    const h = createHash("sha256");
    createReadStream(path)
      .on("data", (c) => h.update(c))
      .on("error", rej)
      .on("end", () => res(h.digest("hex")));
  });
}

function jwkFromPrivate(hex: string): EcdsaPublicKey {
  const pub = p256.getPublicKey(Buffer.from(hex, "hex"), false);
  return {
    kty: "EC",
    crv: "P-256",
    x: base64urlEncode(pub.slice(1, 33)),
    y: base64urlEncode(pub.slice(33, 65)),
  };
}

function jwkToDecimals(jwk: EcdsaPublicKey): [string, string] {
  const toDec = (b64u: string) =>
    BigInt("0x" + Buffer.from(b64u, "base64url").toString("hex")).toString();
  return [toDec(jwk.x), toDec(jwk.y)];
}

// The SDK's witness calculator takes bigint-valued inputs; the JSON form
// carries decimal strings.
function toWitnessInputs(json: string): Record<string, unknown> {
  return JSON.parse(json, (_k, v) =>
    typeof v === "string" && /^-?\d+$/.test(v) ? BigInt(v) : v,
  );
}

function expectEqual(label: string, actual: bigint[], expected: string[]): void {
  const a = actual.map((v) => v.toString());
  if (a.length !== expected.length || a.some((v, i) => v !== expected[i])) {
    throw new Error(
      `self-check failed: ${label}\n  witness : ${a.join(",")}\n  expected: ${expected.join(",")}`,
    );
  }
}

async function main(): Promise<void> {
  const { circomBuild, out } = parseArgs();
  const jwtR1cs = join(circomBuild, "jwt_2k", "jwt_2k.r1cs");
  const showR1cs = join(circomBuild, "show", "show.r1cs");

  // WitnessCalculator wants `<name>.wasm` in a flat directory.
  const wasmDir = await mkdtemp(join(tmpdir(), "openac-wasm-"));
  try {
    await copyFile(join(circomBuild, "jwt_2k", "jwt_2k_js", "jwt_2k.wasm"), join(wasmDir, "jwt_2k.wasm"));
    await copyFile(join(circomBuild, "show", "show_js", "show.wasm"), join(wasmDir, "show.wasm"));
    await generate(out, wasmDir, jwtR1cs, showR1cs);
  } finally {
    await rm(wasmDir, { recursive: true, force: true });
  }
}

async function generate(
  out: string,
  wasmDir: string,
  jwtR1cs: string,
  showR1cs: string,
): Promise<void> {
  const wc = new WitnessCalculator(wasmDir);
  await wc.init();

  const cred = generateDummyCredential({
    size: SIZE,
    nbf: NBF,
    exp: EXP,
    issuer: ISSUER_URL,
  });
  const profile = { now: NOW };
  const credential = Credential.parse(cred.jwt, cred.disclosures, profile);
  const deviceKey = credential.deviceBindingKey;
  if (!deviceKey) throw new Error("credential has no device binding key");

  for (const c of credential.claims) {
    if (c.raw.length < 56) {
      throw new Error(`disclosure ${c.name} is ${c.raw.length} bytes, circuit needs >= 56`);
    }
  }

  const issuerKey = cred.issuerPublicKey;
  const otherIssuerKey = jwkFromPrivate(OTHER_ISSUER_PRIVATE_KEY);

  const requests: RequestDef[] = [
    {
      id: "A",
      verifier: "Corner bar",
      title: "Over 18",
      policyText: "roc_birthday <= 0961112 (born on or before 2007-11-12)",
      nonce: "bar-session-2026-11-12-A-7f3a91",
      policy: { claim: "roc_birthday", op: "<=", value: new Date(Date.UTC(2007, 10, 12)) },
    },
    {
      id: "B",
      verifier: "Vintage club",
      title: "Born before 1990",
      policyText: "roc_birthday <= 0781231 (born on or before 1989-12-31)",
      nonce: "club-session-2026-11-12-B-2c8e04",
      policy: { claim: "roc_birthday", op: "<=", value: new Date(Date.UTC(1989, 11, 31)) },
    },
    {
      id: "C",
      verifier: "Corner bar",
      title: "Over 18 (second visit)",
      policyText: "roc_birthday <= 0961112 (born on or before 2007-11-12)",
      nonce: "bar-session-2026-11-12-C-b15d62",
      policy: { claim: "roc_birthday", op: "<=", value: new Date(Date.UTC(2007, 10, 12)) },
    },
    {
      id: "D",
      verifier: "Other issuer's venue",
      title: "Over 18 (trusts another issuer)",
      policyText: "roc_birthday <= 0961112 (born on or before 2007-11-12)",
      nonce: "venue-session-2026-11-12-D-94e0c7",
      policy: { claim: "roc_birthday", op: "<=", value: new Date(Date.UTC(2007, 10, 12)) },
      trustedIssuerKey: otherIssuerKey,
    },
  ];

  // One Prepare serves every request, so its normalization comes from request A.
  // The loop below fails if any other request needs a different one.
  const compiledA = compilePredicateExpression(requests[0]!.policy, credential.claims);
  const birthdayIdx = compiledA.birthdayClaimIndex ?? credential.findBirthdayClaim() ?? 0;
  if (!credential.claims[birthdayIdx]) throw new Error("no birthday claim");

  const signingInputLen = credential.b64Header.length + 1 + credential.b64Payload.length;
  const vcSize = selectVcSizeForSigningInput(signingInputLen);
  if (vcSize !== SIZE) {
    throw new Error(`credential sizes to ${vcSize} (${signingInputLen}B), mobile needs ${SIZE}`);
  }
  const jwtParams = JWT_PARAMS_BY_SIZE[vcSize];
  const jwtInputs = buildJwtCircuitInputs(
    credential,
    issuerKey,
    jwtParams,
    credential.disclosureHashes,
    compiledA.decodeFlags,
    compiledA.claimFormats,
  );
  const jwtInputJson = circuitInputsToJson(jwtInputs);
  const jwtWitness = await wc.calculateJwtWitness(toWitnessInputs(jwtInputJson), vcSize);

  const maxClaims = jwtParams.maxMatches - 2;
  const claimStart = CLAIM_VALUES_WITNESS_START[vcSize];
  const identityStart = CLAIM_IDENTITY_WITNESS_START[vcSize];
  const normalizedClaimValues = jwtWitness.slice(claimStart, claimStart + maxClaims);
  const claimIdentifierHashes = jwtWitness.slice(identityStart, identityStart + maxClaims);
  const normalization = {
    decodeFlags: jwtInputs.decodeFlags,
    claimFormats: jwtInputs.claimFormats.map((v) => Number(v)),
  };

  // Prepare public values: [issuerX, issuerY, decodeFlags.., claimFormats..].
  const preparePublicValuesFor = (key: EcdsaPublicKey): string[] => [
    ...jwkToDecimals(key),
    ...normalization.decodeFlags.map(String),
    ...normalization.claimFormats.map(String),
  ];
  const truePrepareValues = preparePublicValuesFor(issuerKey);
  expectEqual(
    "JWT witness public signals vs issuer key + normalization",
    jwtWitness.slice(1, 1 + truePrepareValues.length),
    truePrepareValues,
  );

  const outRequests = [];
  const showInputJsons = new Map<string, string>();
  for (const req of requests) {
    const deviceSignature = signDeviceNonce(req.nonce, cred.devicePrivateKeyHex);
    const compiled = compilePredicateExpression(req.policy, credential.claims);
    assertNormalizationSupports(normalization, compiled);
    const requiredNorm = requiredNormalization(compiled);
    if (JSON.stringify(requiredNorm) !== JSON.stringify(requiredNormalization(compiledA))) {
      throw new Error(`request ${req.id} needs a different normalization than the shared Prepare`);
    }

    const showInputs = buildShowCircuitInputs(
      DEFAULT_SHOW_PARAMS,
      req.nonce,
      deviceSignature,
      deviceKey,
      {
        normalizedClaimValues,
        claimIdentifierHashes,
        predicates: compiled.predicates,
        logicExpression: compiled.logicExpression,
      },
    );
    const showInputJson = circuitInputsToJson(showInputs);
    showInputJsons.set(req.id, showInputJson);

    // verifier.ts path: statement from nonce + policy only, no credential.
    const showStatement = buildShowStatementPublicValues(
      DEFAULT_SHOW_PARAMS,
      req.nonce,
      compiled.predicates,
      compiled.logicExpression,
    ).map((v) => v.toString());

    const showWitness = await wc.calculateShowWitness(toWitnessInputs(showInputJson));
    const expressionResult = showWitness[1] === 1n;
    expectEqual(
      `Show witness public signals for request ${req.id}`,
      showWitness.slice(1, 2 + showStatement.length),
      [expressionResult ? "1" : "0", ...showStatement],
    );

    outRequests.push({
      id: req.id,
      verifier: req.verifier,
      title: req.title,
      policyText: req.policyText,
      nonce: req.nonce,
      showInput: JSON.parse(showInputJson),
      expected: {
        preparePublicValues: req.trustedIssuerKey
          ? preparePublicValuesFor(req.trustedIssuerKey)
          : truePrepareValues,
        showStatement,
      },
      expectedExpressionResult: expressionResult,
    });
  }

  const byId = new Map(outRequests.map((r) => [r.id, r]));
  const wantResult: Record<string, boolean> = { A: true, B: false, C: true, D: true };
  for (const [id, want] of Object.entries(wantResult)) {
    if (byId.get(id)!.expectedExpressionResult !== want) {
      throw new Error(`request ${id} expression result is not ${want}`);
    }
  }

  const pkg = JSON.parse(await readFile(join(SDK_ROOT, "package.json"), "utf8"));
  const sourceCommit = execFileSync(
    "git",
    ["log", "-1", "--format=%H", "--", ":/wallet-unit-poc/circom/circuits"],
    { cwd: SDK_ROOT, encoding: "utf8" },
  ).trim();

  const bundle = {
    schemaVersion: 1,
    sdkVersion: pkg.version,
    circuit: {
      size: SIZE,
      jwtR1csSha256: await sha256File(jwtR1cs),
      showR1csSha256: await sha256File(showR1cs),
      sourceCommit,
    },
    credential: {
      format: "vc+sd-jwt",
      jwt: cred.jwt,
      disclosures: cred.disclosures,
      header: credential.header,
      payload: credential.payload,
      claims: credential.claims.map((c) => ({ name: c.name, value: c.value })),
      issuer: { iss: ISSUER_URL, publicKeyJwk: issuerKey },
      deviceKey: { publicKeyJwk: deviceKey },
    },
    requests: outRequests,
    scenarios: [
      {
        id: "over18",
        title: "Over 18",
        description: "Alice proves she is over 18. The verifier accepts.",
        presentFor: "A",
        verifyAgainst: "A",
        expect: "accepted",
      },
      {
        id: "policyFalse",
        title: "Born before 1990",
        description: "The proof is valid, but the policy is false for Alice.",
        presentFor: "B",
        verifyAgainst: "B",
        expect: "policy_false",
      },
      {
        id: "replay",
        title: "Replayed proof",
        description: "A proof made for one session is shown to a verifier with a fresh nonce.",
        presentFor: "A",
        verifyAgainst: "C",
        expect: "rejected",
      },
      {
        id: "untrustedIssuer",
        title: "Untrusted issuer",
        description: "The proof is valid, but the verifier trusts a different issuer.",
        presentFor: "D",
        verifyAgainst: "D",
        expect: "rejected",
      },
    ],
  };

  await mkdir(join(out, "flow"), { recursive: true });
  await mkdir(join(out, "circom"), { recursive: true });
  await writeFile(join(out, "flow", "bundle.json"), JSON.stringify(bundle, null, 2) + "\n");
  await writeFile(join(out, "circom", "jwt_input.json"), jwtInputJson);
  await writeFile(join(out, "circom", "show_input.json"), showInputJsons.get("A")!);

  console.log(
    `fixtures ok: ${SIZE}, signing input ${signingInputLen}B, ` +
      `prepare public values ${truePrepareValues.length}, ` +
      `show public values ${1 + outRequests[0]!.expected.showStatement.length}`,
  );
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});

import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as nodeCrypto from "crypto";
// @ts-ignore - snarkjs ships no types
import * as snarkjs from "snarkjs";

import { generateMockData } from "./mock-vc-generator";
import { generateShowCircuitParams, generateShowInputs, signDeviceNonce, nameToBuffer } from "./show";
import { generateIssuerMembershipInputs } from "./issuer-hiding";
import { base64urlToBigInt } from "./utils";
import { PredicateFormat } from "./predicate-types";
import { buildRevocationWitness, createRevocationRegistry, bytesToBigInt } from "./revocation";

// Witness index of claimIdentifierHashes[0] per compiled JWT size (.sym column $2).
// Read from the JWT witness because H(name) can't be computed off-circuit
// (the circuits are over secq256r1; no JS Poseidon matches). Mirrors
// CLAIM_IDENTITY_WITNESS_START in openac-sdk/src/sizing.ts.
const CLAIM_IDENTITY_WITNESS_START: Record<string, number> = {
  default: 3872,
  "1k": 2527,
  "2k": 4075,
  "4k": 7623,
  "8k": 14719,
};

export const CIRCUIT_SIZES: Record<string, number[]> = {
  // "default" matches the params baked into circuits/main/{jwt,show}.circom and writes
  // to inputs/{jwt,show}/default.json (not a sized subfolder).
  default: [1920, 1900, 4, 50, 128],
  "1k": [1280, 960, 4, 50, 128],
  "2k": [2048, 2000, 4, 50, 128],
  "4k": [4096, 4000, 4, 50, 128],
  "8k": [8192, 8000, 4, 50, 128],
};

// Max revocation tree depth of the compiled Show circuit (circuits.json).
const REVOCATION_MAX_DEPTH = 10;

// Predicate operator codes (see eval-predicate.circom).
const OP_LE = 0;

const FILL_RATIO = 0.8;

async function generateInputsForSize(sizeName: string): Promise<void> {
  const params = CIRCUIT_SIZES[sizeName];
  if (!params) {
    throw new Error(`Unknown size '${sizeName}'. Valid sizes: ${Object.keys(CIRCUIT_SIZES).join(", ")}`);
  }

  const [maxMessageLength, maxB64PayloadLength, maxMatches, maxSubstringLength, maxClaimsLength] = params;
  const targetPayloadLength = Math.floor(maxB64PayloadLength * FILL_RATIO);

  console.log(`\n[${sizeName}] Generating inputs...`);
  console.log(`  Circuit params : [${params.join(", ")}]`);
  console.log(
    `  Target payload : ${targetPayloadLength} / ${maxB64PayloadLength} chars (${Math.round(FILL_RATIO * 100)}% fill)`,
  );

  // Default mock claims are [name, roc_birthday]; mark roc_birthday as a ROC date so the
  // JWT circuit normalizes it to a comparable integer that the Show circuit can predicate over.
  const claimFormats = [PredicateFormat.STRING_EQ, PredicateFormat.ROC_DATE];

  const mockData = await generateMockData({
    // Short identifiers so the 1k payload fits with the revocation value.
    issuer: "https://issuer.example",
    subject: "did:example:holder",
    circuitParams: params,
    targetPayloadLength,
    claimFormats,
  });

  const actualPayloadLen = mockData.token.split(".")[1].length;
  console.log(
    `  Actual payload : ${actualPayloadLen} chars (${((actualPayloadLen / maxB64PayloadLength) * 100).toFixed(1)}% fill)`,
  );

  const showParams = generateShowCircuitParams(params);

  const ROC_BIRTHDAY_SLOT = 1;
  if (!mockData.claims[ROC_BIRTHDAY_SLOT]) {
    throw new Error(`Expected mock data to include a roc_birthday claim at index ${ROC_BIRTHDAY_SLOT}`);
  }

  const nonce = nodeCrypto.randomBytes(24).toString("base64url");
  const deviceSignature = signDeviceNonce(nonce, mockData.devicePrivateKey);

  // Pass every claim, in JWT slot order. Show's claimValues must equal the JWT
  // circuit's normalizedClaimValues slot for slot: both go into the shared
  // witness partition, and `comm_W_shared` only matches if the vectors are
  // identical. (Passing just the birthday put it in slot 0 here but slot 1 in
  // the JWT circuit — which went unnoticed while the shared partition was zeros.)
  // Read per-slot attribute identities H(name) from the JWT witness. They can't
  // be hashed off-circuit (secq256r1 — no matching JS Poseidon), so we run the
  // compiled jwt witnesscalc and pull them out. They travel into Show via the
  // shared partition, so comm_W_shared matches Prepare.
  let claimIdentifierHashes: bigint[] = [];
  const identityStart = CLAIM_IDENTITY_WITNESS_START[sizeName];
  if (identityStart !== undefined) {
    const jwtName = sizeName === "default" ? "jwt" : `jwt_${sizeName}`;
    const jwtWasm = path.resolve(__dirname, "..", "build", jwtName, `${jwtName}_js`, `${jwtName}.wasm`);
    const wtnsPath = path.join(os.tmpdir(), `${jwtName}-geninputs.wtns`);
    await snarkjs.wtns.calculate(mockData.circuitInputs, jwtWasm, wtnsPath);
    const witness: (bigint | string)[] = await snarkjs.wtns.exportJson(wtnsPath);
    for (let i = 0; i < showParams.nClaims; i++) {
      claimIdentifierHashes.push(BigInt(witness[identityStart + i]));
    }
    fs.rmSync(wtnsPath, { force: true });
  }

  const issuer = {
    x: base64urlToBigInt(mockData.issuerKey.x),
    y: base64urlToBigInt(mockData.issuerKey.y),
  };
  const showInputs = generateShowInputs(
    showParams,
    nonce,
    deviceSignature,
    mockData.deviceKey,
    mockData.claims,
    [], // logicExpr (default)
    [], // normalizedClaimValues (derived from claims)
    claimIdentifierHashes,
    // Issuer hiding: Show must see the same issuer key the JWT circuit verified.
    generateIssuerMembershipInputs(issuer),
  );

  // Show predicate: claim[ROC_BIRTHDAY_SLOT] <= 1070101 (ROC adult cutoff).
  showInputs.predicateLen = 1n;
  showInputs.predicateClaimRefs[0] = BigInt(ROC_BIRTHDAY_SLOT);
  showInputs.predicateOps[0] = BigInt(OP_LE);
  showInputs.predicateRhsValues[0] = 1070101n;
  showInputs.tokenTypes[0] = 0n;
  showInputs.tokenValues[0] = 0n;
  showInputs.exprLen = 1n;

  // The predicate names its attribute; Show hashes it to the identity it enforces.
  // Slot ROC_BIRTHDAY_SLOT is "roc_birthday" (see the mock claims above).
  const lhsName = nameToBuffer(mockData.claims[ROC_BIRTHDAY_SLOT] ? "roc_birthday" : "");
  showInputs.predicateClaimNames[0] = lhsName.bytes;
  showInputs.predicateClaimNameLens[0] = lhsName.len;

  // Non-revocation proof against a registry holding a few unrelated commitments.
  const registry = createRevocationRegistry(
    Array.from({ length: 5 }, () => bytesToBigInt(nodeCrypto.randomBytes(32))),
  );
  Object.assign(
    showInputs,
    buildRevocationWitness(issuer, mockData.revocationValue, registry, REVOCATION_MAX_DEPTH),
  );

  const circomDir = path.resolve(__dirname, "..");
  // The "default" pseudo-size writes to inputs/{jwt,show}/default.json directly,
  // matching the params in circuits/main/{jwt,show}.circom.
  const isDefault = sizeName === "default";
  const jwtOutputDir = isDefault ? path.join(circomDir, "inputs", "jwt") : path.join(circomDir, "inputs", "jwt", sizeName);
  const showOutputDir = isDefault ? path.join(circomDir, "inputs", "show") : path.join(circomDir, "inputs", "show", sizeName);

  fs.mkdirSync(jwtOutputDir, { recursive: true });
  fs.mkdirSync(showOutputDir, { recursive: true });

  const jwtOutputPath = path.join(jwtOutputDir, "default.json");
  const showOutputPath = path.join(showOutputDir, "default.json");

  const bigintReplacer = (_key: string, value: any) => (typeof value === "bigint" ? value.toString() : value);

  fs.writeFileSync(jwtOutputPath, JSON.stringify(mockData.circuitInputs, bigintReplacer, 2));
  fs.writeFileSync(showOutputPath, JSON.stringify(showInputs, bigintReplacer, 2));

  console.log(`  JWT  inputs → ${path.relative(circomDir, jwtOutputPath)}`);
  console.log(`  Show inputs → ${path.relative(circomDir, showOutputPath)}`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    console.log(`
Usage: npx ts-node src/generate-inputs.ts [options]

Options:
  --size <size>  Generate inputs for a specific circuit size (1k | 2k | 4k | 8k)
  --all          Generate inputs for all sizes (1k, 2k, 4k, 8k)
  -h, --help     Show this help message

Examples:
  npx ts-node src/generate-inputs.ts --size 2k
  npx ts-node src/generate-inputs.ts --all
`);
    process.exit(0);
  }

  if (args.includes("--all")) {
    for (const sizeName of Object.keys(CIRCUIT_SIZES)) {
      await generateInputsForSize(sizeName);
    }
    console.log("\nAll inputs generated successfully.");
    return;
  }

  const sizeIdx = args.indexOf("--size");
  if (sizeIdx === -1 || !args[sizeIdx + 1]) {
    console.error("Error: --size <size> is required (or use --all).");
    process.exit(1);
  }

  const sizeName = args[sizeIdx + 1];
  await generateInputsForSize(sizeName);
  console.log("\nDone.");
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});

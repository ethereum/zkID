import * as fs from "fs";
import * as path from "path";
import * as nodeCrypto from "crypto";

import { createTestMdocCredential } from "./mdoc-fixture";
import { generateMdocCircuitParams, generateMdocInputs, parseMdocClaims, type MdocClaimType } from "./mdoc";
import { generateShowInputs, signDeviceNonce } from "./show";
import { bindPredicateName, hashClaimName } from "./claim-identity.ts";

// Mirrors circuits/main/mdoc.circom: MDOC(1792, 256, 4, 32, 64).
const MDOC_PARAMS: [number, number, number, number, number] = [1792, 256, 4, 32, 64];

// Mirrors circuits/main/show.circom: Show(2, 2, 8, 64).
const SHOW_PARAMS = { nClaims: 2, maxPredicates: 2, maxLogicTokens: 8, valueBits: 64 };

const OP_LE = 0;

function ymdToYyyymmdd(ymd: string): bigint {
  const [y, m, d] = ymd.split("-").map(Number);
  return BigInt(y * 10000 + m * 100 + d);
}

function packString(s: string): bigint {
  const buf = Buffer.from(s, "utf-8");
  let n = 0n;
  for (let i = 0; i < buf.length; i++) n += BigInt(buf[i]) * 256n ** BigInt(i);
  return n;
}

function devicePubKeyJwk(x: Uint8Array, y: Uint8Array) {
  return {
    kty: "EC" as const,
    crv: "P-256" as const,
    x: Buffer.from(x).toString("base64url"),
    y: Buffer.from(y).toString("base64url"),
  };
}

const bigintReplacer = (_key: string, value: any) => (typeof value === "bigint" ? value.toString() : value);

async function main(): Promise<void> {
  const circomDir = path.resolve(__dirname, "..");

  const cred = await createTestMdocCredential();

  const claimConfig: Record<string, { type: MdocClaimType }> = {
    birth_date: { type: "date" },
    resident_state: { type: "string" },
  };

  const params = generateMdocCircuitParams([...MDOC_PARAMS]);
  const { claims, deviceKeyPos } = parseMdocClaims(cred.tbsData, cred.items, cred.deviceKeyX, claimConfig);
  const mdocInputs = generateMdocInputs(
    params,
    cred.tbsData,
    cred.signature,
    cred.issuerPubRaw,
    claims,
    deviceKeyPos,
  );

  const mdocDir = path.join(circomDir, "inputs", "mdoc");
  fs.mkdirSync(mdocDir, { recursive: true });
  const mdocPath = path.join(mdocDir, "default.json");
  fs.writeFileSync(mdocPath, JSON.stringify(mdocInputs, bigintReplacer, 2));
  console.log(`MDOC inputs  → ${path.relative(circomDir, mdocPath)}`);

  const normalizedClaimValues = [ymdToYyyymmdd(cred.claims.birth_date), packString(cred.claims.resident_state)];

  const nonce = nodeCrypto.randomBytes(24).toString("base64url");
  const deviceSignature = signDeviceNonce(nonce, cred.devPrvHex);

  // Both slots: MdocCircuit::shared() commits the mdoc circuit's own identities,
  // so Show must carry the same values or comm_W_shared will not match.
  const claimIdentifierHashes = [
    await hashClaimName("birth_date"),
    await hashClaimName("resident_state"),
  ];

  const showInputs = generateShowInputs(
    SHOW_PARAMS,
    nonce,
    deviceSignature,
    devicePubKeyJwk(cred.deviceKeyX, cred.deviceKeyY),
    [],
    [],
    normalizedClaimValues,
    claimIdentifierHashes,
  );

  showInputs.predicateLen = 1n;
  showInputs.predicateClaimRefs[0] = 0n;
  showInputs.predicateOps[0] = BigInt(OP_LE);
  showInputs.predicateRhsValues[0] = 20000101n;
  showInputs.tokenTypes[0] = 0n;
  showInputs.tokenValues[0] = 0n;
  showInputs.exprLen = 1n;

  // Show rejects a zero identity as a padding-slot wildcard.
  await bindPredicateName(showInputs, 0, 0, "birth_date");

  const showDir = path.join(circomDir, "inputs", "show");
  fs.mkdirSync(showDir, { recursive: true });
  const showPath = path.join(showDir, "mdoc.json");
  fs.writeFileSync(showPath, JSON.stringify(showInputs, bigintReplacer, 2));
  console.log(`Show inputs  → ${path.relative(circomDir, showPath)}`);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});

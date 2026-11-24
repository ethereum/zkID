import * as fs from "fs";
import * as path from "path";
import * as nodeCrypto from "crypto";

import {
  buildJsonLdPrepareInputs,
  JSONLD_BASE,
  JSONLD_FORMAT,
  normalizeJsonLdValue,
} from "./jsonld/build-inputs";
import {
  FIXTURE_DEVICE_JWK,
  FIXTURE_NQUADS,
  FIXTURE_PROOF_NQUADS,
  loadTestIssuer,
  proofHashOf,
  signJsonLd,
} from "./jsonld/test-fixture";
import { generateShowInputs, LogicToken, nameToBuffer, predicateToken, signDeviceNonce } from "./show";

// Mirrors circuits.json `jsonld`: JSONLD(2240, 2, 128, 31, 64, 252).
// Mirrors circuits/main/show.circom: Show(2, 2, 8, 64).
const SHOW_PARAMS = { nClaims: 2, maxPredicates: 2, maxLogicTokens: 8, valueBits: 64 };

const OP_LE = 0n;
const OP_EQ = 2n;

// dateOfBirth <= this means "at least 18 on 2026-10-27".
const ADULT_DOB_CUTOFF = 20081027n;

const bigintReplacer = (_key: string, value: unknown) => (typeof value === "bigint" ? value.toString() : value);

function main(): void {
  const circomDir = path.resolve(__dirname, "..");

  // TEST ONLY: the issuer key and the fixture credential are throwaway.
  const issuer = loadTestIssuer();
  const nquads = FIXTURE_NQUADS();
  const proofHash = proofHashOf(FIXTURE_PROOF_NQUADS());

  const claims = [
    { name: "dateOfBirth", format: JSONLD_FORMAT.isoDate },
    { name: "nationality", format: JSONLD_FORMAT.digest64 },
  ];

  const { inputs, meta } = buildJsonLdPrepareInputs({
    nquads,
    proofHash,
    signature: signJsonLd(nquads, proofHash, issuer),
    issuerPublicKey: { x: issuer.x, y: issuer.y },
    base: JSONLD_BASE,
    claims,
  });

  const jsonldDir = path.join(circomDir, "inputs", "jsonld");
  fs.mkdirSync(jsonldDir, { recursive: true });
  const jsonldPath = path.join(jsonldDir, "default.json");
  fs.writeFileSync(jsonldPath, JSON.stringify(inputs, bigintReplacer, 2));
  console.log(`JSONLD inputs → ${path.relative(circomDir, jsonldPath)}`);

  // The device key in the credential is the key whose private half the fixture ships.
  const deviceJwk = FIXTURE_DEVICE_JWK();
  const nonce = nodeCrypto.randomBytes(24).toString("base64url");
  const deviceSignature = signDeviceNonce(nonce, Buffer.from(deviceJwk.d, "base64url"));

  const showInputs = generateShowInputs(
    SHOW_PARAMS,
    nonce,
    deviceSignature,
    { kty: "EC", crv: "P-256", x: deviceJwk.x, y: deviceJwk.y },
    [],
    [predicateToken(0), predicateToken(1), LogicToken.AND],
    meta.normalizedClaimValues,
    meta.claimIdentifierHashes,
  );

  const nationality = nameToBuffer("nationality");
  const dateOfBirth = nameToBuffer("dateOfBirth");

  showInputs.predicateLen = 2n;
  showInputs.predicateClaimRefs = [0n, 1n];
  showInputs.predicateOps = [OP_LE, OP_EQ];
  showInputs.predicateRhsIsRef = [0n, 0n];
  showInputs.predicateRhsValues = [ADULT_DOB_CUTOFF, normalizeJsonLdValue(JSONLD_FORMAT.digest64, "Ruritanian")];
  showInputs.predicateClaimNames[0] = dateOfBirth.bytes;
  showInputs.predicateClaimNameLens[0] = dateOfBirth.len;
  showInputs.predicateClaimNames[1] = nationality.bytes;
  showInputs.predicateClaimNameLens[1] = nationality.len;

  const showDir = path.join(circomDir, "inputs", "show");
  fs.mkdirSync(showDir, { recursive: true });
  const showPath = path.join(showDir, "jsonld.json");
  fs.writeFileSync(showPath, JSON.stringify(showInputs, bigintReplacer, 2));
  console.log(`Show inputs   → ${path.relative(circomDir, showPath)}`);
}

main();

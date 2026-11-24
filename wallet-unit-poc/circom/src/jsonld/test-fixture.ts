import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha2";
import * as fs from "fs";
import * as path from "path";
import { jsonLdSigningInput, JSONLD_BASE } from "./build-inputs.ts";

// TEST ONLY. The issuer key and the credential below are throwaway fixtures;
// nothing here is a secret.
const FIXTURE_DIR = path.resolve(__dirname, "../../inputs/jsonld");

export function readFixture(name: string): string {
  return fs.readFileSync(path.join(FIXTURE_DIR, "fixtures", name), "utf8");
}

export const FIXTURE_NQUADS = (): string => readFixture("sample-unsigned.nquads");
export const FIXTURE_PROOF_NQUADS = (): string => readFixture("sample-proof-options.nquads");
export const FIXTURE_DEVICE_JWK = () => JSON.parse(readFixture("sample-device-key.jwk.json"));
export { JSONLD_BASE };

export interface TestIssuer {
  d: bigint;
  x: bigint;
  y: bigint;
}

export function loadTestIssuer(): TestIssuer {
  const k = JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, "test-issuer-key.json"), "utf8"));
  return { d: BigInt("0x" + k.d), x: BigInt("0x" + k.x), y: BigInt("0x" + k.y) };
}

/** Signs SHA-256(header || "." || proofHash || SHA-256(nquads)) the way the circuit expects. */
export function signJsonLd(nquads: string, proofHash: Uint8Array, issuer: TestIssuer = loadTestIssuer()) {
  const docHash = sha256(new TextEncoder().encode(nquads));
  const msgHash = sha256(jsonLdSigningInput(proofHash, docHash));
  const sig = p256.sign(msgHash, issuer.d, { lowS: false });
  return { r: sig.r, s: sig.s };
}

export function proofHashOf(proofNquads: string): Uint8Array {
  return new Uint8Array(sha256(new TextEncoder().encode(proofNquads)));
}

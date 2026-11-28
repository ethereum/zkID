import { describe, it, expect } from "vitest";
import { createHash } from "crypto";
import { RevocationRegistry, poseidonScheme } from "@coordination-network/revocation-registry";

import { p256 } from "@noble/curves/nist.js";

import {
  Credential,
  REVOCATION_MAX_DEPTH,
  acceptRevocationRoots,
  buildRevocationWitness,
  computeRevocationCommitment,
  createRevocationRegistry,
  decodeRevocationValue,
  encodeRevocationValue,
  generateRevocationValue,
  revocationRegistryFromLeaves,
} from "../src/index.js";
import { generateDummyCredential } from "../src/testing/index.js";
import { fromLimbs } from "../src/revocation.js";
import { Prover, WitnessCalculator, circuitInputsToJson, compilePredicateExpression } from "../src/index.js";
import { buildJwtCircuitInputs } from "../src/inputs/jwt-input-builder.js";
import { issuerPublicKeyToPoint } from "../src/inputs/issuer-key.js";
import { JWT_PARAMS_BY_SIZE } from "../src/sizing.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const ASSETS_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "assets");

const point = (k: bigint) => {
  const { x, y } = p256.Point.BASE.multiply(k).toAffine();
  return { x, y };
};
const ISSUER = point(3n);
const P256_P = p256.CURVE.p;
const OTHER_ISSUER = point(5n);

const commitments = (n: number) =>
  Array.from({ length: n }, () => computeRevocationCommitment(ISSUER, generateRevocationValue()));

const be32 = (v: bigint) => Buffer.from(v.toString(16).padStart(64, "0"), "hex");

const sha256Words = (...words: bigint[]) =>
  BigInt("0x" + createHash("sha256").update(Buffer.concat(words.map(be32))).digest("hex"));

describe("revocation commitments", () => {
  it("is sha256(be32(x) || be32(y) || be32(value) || be32(3))", () => {
    const value = 7n;

    expect(computeRevocationCommitment(ISSUER, value)).toBe(sha256Words(ISSUER.x, ISSUER.y, value, 3n));
  });

  it("binds the issuer key: the same value gives different commitments under different issuers", () => {
    const value = generateRevocationValue();

    expect(computeRevocationCommitment(ISSUER, value)).not.toBe(computeRevocationCommitment(OTHER_ISSUER, value));
  });

  it("accepts the issuer key as a JWK", () => {
    const cred = generateDummyCredential({ size: "1k" });

    expect(computeRevocationCommitment(cred.issuerPublicKey, cred.revocationValue)).toBe(
      computeRevocationCommitment(issuerPublicKeyToPoint(cred.issuerPublicKey), cred.revocationValue),
    );
  });

  it("rejects an issuer point off P-256 or with a coordinate not below p", () => {
    const value = generateRevocationValue();

    expect(() => computeRevocationCommitment({ x: ISSUER.x, y: ISSUER.y + 1n }, value)).toThrow(/P-256/);
    expect(() => computeRevocationCommitment({ x: ISSUER.x, y: ISSUER.y + P256_P }, value)).toThrow(/P-256/);
  });

  it("rejects a value outside (0, 2^256)", () => {
    expect(() => computeRevocationCommitment(ISSUER, 0n)).toThrow(/\(0, 2\^256\)/);
    expect(() => computeRevocationCommitment(ISSUER, 1n << 256n)).toThrow(/\(0, 2\^256\)/);
  });

  it("round-trips the value through the claim encoding", () => {
    const value = generateRevocationValue();

    expect(decodeRevocationValue(encodeRevocationValue(value))).toBe(value);
  });

  it("rejects an all-zero claim value at decode", () => {
    expect(() => decodeRevocationValue("A".repeat(43))).toThrow(/\(0, 2\^256\)/);
  });

  it("is carried by the dummy credential", () => {
    const cred = generateDummyCredential({ size: "1k" });
    const parsed = Credential.parse(cred.jwt, cred.disclosures);

    expect(parsed.revocationValue).toBe(cred.revocationValue);
  });
});

describe("buildRevocationWitness", () => {
  const value = generateRevocationValue();
  const commitment = computeRevocationCommitment(ISSUER, value);

  it("proves against root 0 for an empty registry", () => {
    const w = buildRevocationWitness(ISSUER, value, createRevocationRegistry());

    expect(w.revocationDepth).toBe(0n);
    expect(w.revocationLeafValue).toEqual([0n, 0n]);
    expect(w.revocationSiblings).toHaveLength(REVOCATION_MAX_DEPTH);
    expect(fromLimbs(w.revocationValue[0]!, w.revocationValue[1]!)).toBe(value);
  });

  it("uses the low leaf that brackets the commitment", () => {
    const registry = createRevocationRegistry(commitments(9));
    const w = buildRevocationWitness(ISSUER, value, registry);
    const low = fromLimbs(w.revocationLeafValue[0]!, w.revocationLeafValue[1]!);
    const next = fromLimbs(w.revocationLeafNextValue[0]!, w.revocationLeafNextValue[1]!);

    expect(low < commitment && (next === 0n || commitment < next)).toBe(true);
    // Promoted (unpaired) levels add no sibling, so the path can be shorter than the depth.
    expect(w.revocationDepth > 0n && w.revocationDepth <= BigInt(registry.depth)).toBe(true);
    expect(w.revocationSiblings).toHaveLength(REVOCATION_MAX_DEPTH);
  });

  it("refuses a revoked credential", () => {
    const registry = createRevocationRegistry([...commitments(3), commitment]);

    expect(() => buildRevocationWitness(ISSUER, value, registry)).toThrow(/revoked/);
  });

  it("does not treat the same value under another issuer as revoked", () => {
    const registry = createRevocationRegistry([...commitments(3), computeRevocationCommitment(OTHER_ISSUER, value)]);

    expect(() => buildRevocationWitness(ISSUER, value, registry)).not.toThrow();
    expect(() => buildRevocationWitness(OTHER_ISSUER, value, registry)).toThrow(/revoked/);
  });

  it("refuses a registry over another hash", () => {
    const poseidon = new RevocationRegistry([1n, 2n], poseidonScheme);

    expect(() => buildRevocationWitness(ISSUER, value, poseidon)).toThrow(/sha256Scheme/);
  });

  it("works from a registry rebuilt from its leaf slots", () => {
    const registry = createRevocationRegistry(commitments(5));
    const synced = revocationRegistryFromLeaves(registry.leafSlots);

    expect(synced.root).toBe(registry.root);
    expect(buildRevocationWitness(ISSUER, value, synced)).toEqual(
      buildRevocationWitness(ISSUER, value, registry),
    );
  });
});

describe("revocationValueIndex", () => {
  it("is a byte offset the JWT circuit accepts, with non-ASCII before the claim", async () => {
    const cred = generateDummyCredential({ size: "1k", issuer: "https://issuer.example/Müller-Straße" });
    const credential = Credential.parse(cred.jwt, cred.disclosures);
    const inputs = buildJwtCircuitInputs(
      credential,
      cred.issuerPublicKey,
      JWT_PARAMS_BY_SIZE["1k"],
      credential.disclosureHashes,
      [],
    );
    const payload = Buffer.from(credential.b64Payload, "base64url");

    expect(payload.indexOf('"revocation_value":"')).toBe(inputs.revocationValueIndex);

    const calculator = new WitnessCalculator(ASSETS_DIR);
    await calculator.init();
    const witness = await calculator.calculateJwtWitness(
      JSON.parse(circuitInputsToJson(inputs), (_k, v) =>
        typeof v === "string" && /^\d+$/.test(v) ? BigInt(v) : v,
      ),
      "1k",
    );
    expect(witness[0]).toBe(1n);
  }, 120_000);
});

describe("present", () => {
  it("rejects a request without revocation inputs", async () => {
    const cred = generateDummyCredential({ size: "1k" });
    const predicates = { claim: "roc_birthday", op: "<=" as const, value: "0950101", format: "date" as const };
    const compiled = compilePredicateExpression(
      predicates,
      Credential.parse(cred.jwt, cred.disclosures).claims,
    );
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const prover = new Prover({} as any);

    await expect(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      prover.present({
        precomputed: {
          credential: { jwt: cred.jwt, disclosures: cred.disclosures },
          claimNormalization: { decodeFlags: compiled.decodeFlags, claimFormats: compiled.claimFormats },
        },
        verifierNonce: "missing-revocation-nonce",
        devicePrivateKey: cred.devicePrivateKeyHex,
        predicates,
      } as any),
    ).rejects.toMatchObject({ code: "MISSING_REVOCATION_INPUTS" });
  });
});

describe("acceptRevocationRoots", () => {
  it("accepts exactly the listed roots", () => {
    const check = acceptRevocationRoots([0n, 5n]);

    expect(check(5n)).toBe(true);
    expect(check(6n)).toBe(false);
  });
});

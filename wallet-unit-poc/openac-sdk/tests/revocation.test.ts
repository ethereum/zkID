import { describe, it, expect } from "vitest";
import { createHash } from "crypto";
import { RevocationRegistry, poseidonScheme } from "@coordination-network/revocation-registry";

import {
  Credential,
  REVOCATION_MAX_DEPTH,
  acceptRevocationRoots,
  buildRevocationWitness,
  computeRevocationCommitment,
  createRevocationRegistry,
  decodeRevocationCommitment,
  encodeRevocationCommitment,
  generateRevocationSecret,
  revocationRegistryFromLeaves,
} from "../src/index.js";
import { generateDummyCredential } from "../src/testing/index.js";
import { fromLimbs } from "../src/revocation.js";
import { Prover, WitnessCalculator, circuitInputsToJson, compilePredicateExpression } from "../src/index.js";
import { buildJwtCircuitInputs } from "../src/inputs/jwt-input-builder.js";
import { JWT_PARAMS_BY_SIZE } from "../src/sizing.js";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const ASSETS_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "assets");

const commitments = (n: number) =>
  Array.from({ length: n }, () => computeRevocationCommitment(generateRevocationSecret()));

describe("revocation commitments", () => {
  it("is sha256 of the 32-byte secret and round-trips through the claim encoding", () => {
    const secret = new Uint8Array(32).fill(7);
    const commitment = computeRevocationCommitment(secret);

    expect(commitment).toBe(
      BigInt("0x" + createHash("sha256").update(secret).digest("hex")),
    );
    expect(computeRevocationCommitment(Buffer.from(secret).toString("hex"))).toBe(commitment);
    expect(decodeRevocationCommitment(encodeRevocationCommitment(commitment))).toBe(commitment);
  });

  it("rejects secrets that are not 32 bytes", () => {
    expect(() => computeRevocationCommitment(new Uint8Array(31))).toThrow(/32 bytes/);
  });

  it("is carried by the dummy credential", () => {
    const cred = generateDummyCredential({ size: "1k" });
    const parsed = Credential.parse(cred.jwt, cred.disclosures);

    expect(parsed.revocationCommitment).toBe(cred.revocationCommitment);
    expect(computeRevocationCommitment(cred.revocationSecretHex)).toBe(cred.revocationCommitment);
  });
});

describe("buildRevocationWitness", () => {
  const secret = generateRevocationSecret();
  const commitment = computeRevocationCommitment(secret);

  it("proves against root 0 for an empty registry", () => {
    const w = buildRevocationWitness(secret, commitment, createRevocationRegistry());

    expect(w.revocationDepth).toBe(0n);
    expect(w.revocationLeafValue).toEqual([0n, 0n]);
    expect(w.revocationSiblings).toHaveLength(REVOCATION_MAX_DEPTH);
    expect(fromLimbs(w.revocationCommitment[0]!, w.revocationCommitment[1]!)).toBe(commitment);
  });

  it("uses the low leaf that brackets the commitment", () => {
    const registry = createRevocationRegistry(commitments(9));
    const w = buildRevocationWitness(secret, commitment, registry);
    const low = fromLimbs(w.revocationLeafValue[0]!, w.revocationLeafValue[1]!);
    const next = fromLimbs(w.revocationLeafNextValue[0]!, w.revocationLeafNextValue[1]!);

    expect(low < commitment && (next === 0n || commitment < next)).toBe(true);
    // Promoted (unpaired) levels add no sibling, so the path can be shorter than the depth.
    expect(w.revocationDepth > 0n && w.revocationDepth <= BigInt(registry.depth)).toBe(true);
    expect(w.revocationSiblings).toHaveLength(REVOCATION_MAX_DEPTH);
  });

  it("refuses a revoked commitment", () => {
    const registry = createRevocationRegistry([...commitments(3), commitment]);

    expect(() => buildRevocationWitness(secret, commitment, registry)).toThrow(/revoked/);
  });

  it("refuses a secret that does not open the commitment", () => {
    expect(() =>
      buildRevocationWitness(generateRevocationSecret(), commitment, createRevocationRegistry()),
    ).toThrow(/does not match/);
  });

  it("refuses a registry over another hash", () => {
    const poseidon = new RevocationRegistry([1n, 2n], poseidonScheme);

    expect(() => buildRevocationWitness(secret, commitment, poseidon)).toThrow(/sha256Scheme/);
  });

  it("works from a registry rebuilt from its leaf slots", () => {
    const registry = createRevocationRegistry(commitments(5));
    const synced = revocationRegistryFromLeaves(registry.leafSlots);

    expect(synced.root).toBe(registry.root);
    expect(buildRevocationWitness(secret, commitment, synced)).toEqual(
      buildRevocationWitness(secret, commitment, registry),
    );
  });
});

describe("revocationCommitmentIndex", () => {
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

    expect(payload.indexOf('"revocation_commitment":"')).toBe(inputs.revocationCommitmentIndex);

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

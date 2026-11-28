import { describe, it, expect } from "vitest";
import { Credential } from "../src/index.js";
import {
  generateDummyCredential,
  JWT_PARAMS_BY_SIZE,
} from "../src/testing/index.js";
import type { VcSize } from "../src/wasm-bridge.js";

const SIZES: VcSize[] = ["1k", "2k", "4k", "8k"];

describe("generateDummyCredential", () => {
  for (const size of SIZES) {
    it(`produces a JWT that fits the ${size} circuit's maxMessageLength`, () => {
      const cred = generateDummyCredential({ size });
      const params = JWT_PARAMS_BY_SIZE[size];

      expect(cred.meta.signingInputByteLength).toBeLessThanOrEqual(params.maxMessageLength);
      expect(cred.meta.targetSize).toBe(size);
      expect(cred.meta.targetMaxMessageLength).toBe(params.maxMessageLength);
    });
  }

  it("produces a JWT the SDK Credential parser can read", () => {
    const cred = generateDummyCredential({ size: "1k" });
    const parsed = Credential.parse(cred.jwt, cred.disclosures);
    expect(parsed.deviceBindingKey).not.toBeNull();
    expect(parsed.deviceBindingKey!.x).toBe(cred.devicePublicKey.x);
    expect(parsed.deviceBindingKey!.y).toBe(cred.devicePublicKey.y);
    expect(parsed.claims.length).toBeGreaterThanOrEqual(2);
  });

  it("gives each default credential its own revocation value", () => {
    const a = generateDummyCredential({ size: "1k" });
    const b = generateDummyCredential({ size: "1k" });
    expect(a.revocationValue).not.toBe(b.revocationValue);
  });

  it("default keys are deterministic", () => {
    const a = generateDummyCredential({ size: "1k" });
    const b = generateDummyCredential({ size: "1k" });
    expect(a.devicePublicKey.x).toBe(b.devicePublicKey.x);
    expect(a.devicePublicKey.y).toBe(b.devicePublicKey.y);
    expect(a.issuerPublicKey.x).toBe(b.issuerPublicKey.x);
    expect(a.devicePrivateKeyHex).toBe(b.devicePrivateKeyHex);
  });

  it("custom claims appear in the credential", () => {
    const cred = generateDummyCredential({
      size: "1k",
      claims: [
        { key: "country", value: "US" },
        { key: "age_over_18", value: "true" },
      ],
    });
    const parsed = Credential.parse(cred.jwt, cred.disclosures);
    const keys = parsed.claims.map((c) => c.name);
    expect(keys).toContain("country");
    expect(keys).toContain("age_over_18");
  });
});

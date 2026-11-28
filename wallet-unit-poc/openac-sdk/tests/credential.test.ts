import { describe, it, expect } from "vitest";
import { Credential } from "../src/credential.js";
import {
  base64urlToBase64,
  base64Decode,
  base64Encode,
  base64urlEncode,
  bytesToBigInt,
  bigintToBytes,
  sha256Pad,
  stringToPaddedBigIntArray,
  encodeClaims,
  modInverse,
  P256_SCALAR_ORDER,
} from "../src/utils.js";

function createMockJwt() {
  const header = { alg: "ES256", typ: "vc+sd-jwt" };
  const payload = {
    sub: "did:key:test",
    iss: "did:key:issuer",
    cnf: {
      jwk: {
        kty: "EC" as const,
        crv: "P-256" as const,
        x: "dGVzdC14LWNvb3JkaW5hdGUtZm9yLXAyNTYtY3VydmU",
        y: "dGVzdC15LWNvb3JkaW5hdGUtZm9yLXAyNTYtY3VydmU",
      },
    },
    vc: {
      credentialSubject: {
        _sd: ["hash1", "hash2"],
        _sd_alg: "sha-256",
      },
    },
  };

  const b64Header = base64urlEncode(
    new TextEncoder().encode(JSON.stringify(header)),
  );
  const b64Payload = base64urlEncode(
    new TextEncoder().encode(JSON.stringify(payload)),
  );
  const b64Signature = base64urlEncode(new Uint8Array(64));
  const jwt = `${b64Header}.${b64Payload}.${b64Signature}`;

  const disclosure1 = base64urlEncode(
    new TextEncoder().encode(JSON.stringify(["salt1", "name", "John Doe"])),
  );
  const disclosure2 = base64urlEncode(
    new TextEncoder().encode(
      JSON.stringify(["salt2", "roc_birthday", "1040605"]),
    ),
  );

  return { jwt, disclosures: [disclosure1, disclosure2], header, payload };
}

describe("Credential", () => {
  describe("parse", () => {
    it("should parse a valid JWT with disclosures", () => {
      const { jwt, disclosures } = createMockJwt();
      const cred = Credential.parse(jwt, disclosures);

      expect(cred.header.alg).toBe("ES256");
      expect(cred.payload.sub).toBe("did:key:test");
      expect(cred.claims).toHaveLength(2);
      expect(cred.claims[0]!.name).toBe("name");
      expect(cred.claims[0]!.value).toBe("John Doe");
      expect(cred.claims[1]!.name).toBe("roc_birthday");
      expect(cred.claims[1]!.value).toBe("1040605");
    });

    it("should throw on invalid JWT format", () => {
      expect(() => Credential.parse("invalid", [])).toThrow(
        "Invalid JWT format",
      );
      expect(() => Credential.parse("a.b", [])).toThrow("Invalid JWT format");
    });

    it("should compute disclosure digests", () => {
      const { jwt, disclosures } = createMockJwt();
      const cred = Credential.parse(jwt, disclosures);

      for (const claim of cred.claims) {
        expect(claim.digest).toBeTruthy();
        expect(typeof claim.digest).toBe("string");
        expect(claim.digest).not.toMatch(/[+/=]/);
      }
    });
  });

  describe("findBirthdayClaim", () => {
    it("should find roc_birthday claim", () => {
      const { jwt, disclosures } = createMockJwt();
      const cred = Credential.parse(jwt, disclosures);
      const idx = cred.findBirthdayClaim();
      expect(idx).toBe(1);
    });

    it("should return null when no birthday claim exists", () => {
      const jwt = createMockJwt().jwt;
      const disclosure = base64urlEncode(
        new TextEncoder().encode(
          JSON.stringify(["salt", "email", "test@example.com"]),
        ),
      );
      const cred = Credential.parse(jwt, [disclosure]);
      expect(cred.findBirthdayClaim()).toBeNull();
    });
  });

  describe("deviceBindingKey", () => {
    it("should extract device binding key from cnf.jwk", () => {
      const { jwt, disclosures } = createMockJwt();
      const cred = Credential.parse(jwt, disclosures);
      const key = cred.deviceBindingKey;

      expect(key).not.toBeNull();
      expect(key!.kty).toBe("EC");
      expect(key!.crv).toBe("P-256");
      expect(key!.x).toBeTruthy();
      expect(key!.y).toBeTruthy();
    });
  });
});

describe("Utils", () => {
  describe("base64", () => {
    it("should round-trip base64 encode/decode", () => {
      const original = new Uint8Array([1, 2, 3, 4, 5, 255, 0, 128]);
      const encoded = base64Encode(original);
      const decoded = base64Decode(encoded);
      expect(decoded).toEqual(original);
    });

    it("should convert base64url to base64", () => {
      expect(base64urlToBase64("abc-def_ghi")).toBe("abc+def/ghi=");
      expect(base64urlToBase64("ab")).toBe("ab==");
    });
  });

  describe("BigInt conversion", () => {
    it("should convert bytes to BigInt and back", () => {
      const value = 0xdeadbeefcafen;
      const bytes = bigintToBytes(value, 8);
      const result = bytesToBigInt(bytes);
      expect(result).toBe(value);
    });

    it("should handle zero", () => {
      const bytes = bigintToBytes(0n, 4);
      expect(bytesToBigInt(bytes)).toBe(0n);
    });

    it("should reject a value that does not fit", () => {
      expect(() => bigintToBytes(1n << 32n, 4)).toThrow(RangeError);
      expect(() => bigintToBytes(-1n, 4)).toThrow(RangeError);
    });
  });

  describe("sha256Pad", () => {
    it("should pad message to maxLength with SHA-256 padding", () => {
      const msg = new TextEncoder().encode("hello");
      const [padded, len] = sha256Pad(msg, 64);

      // sha256Pad returns the padded length (block-aligned), not the raw message length
      expect(len).toBe(64);
      expect(padded.length).toBe(64);
      expect(padded[0]).toBe(104);
      expect(padded[4]).toBe(111);
      expect(padded[5]).toBe(0x80);
    });

    it("should throw if message too long", () => {
      const msg = new Uint8Array(100);
      expect(() => sha256Pad(msg, 64)).toThrow();
    });
  });

  describe("stringToPaddedBigIntArray", () => {
    it("should convert string to BigInt array", () => {
      const result = stringToPaddedBigIntArray("AB", 4);
      expect(result).toEqual([65n, 66n, 0n, 0n]);
    });
  });

  describe("encodeClaims", () => {
    it("should encode claims with SHA-256 padding", () => {
      const { claimArray, claimLengths } = encodeClaims(["hello"], 2, 128);

      expect(claimLengths[0]).toBe(5n);
      expect(claimLengths[1]).toBe(0n);
      expect(claimArray[0]![0]).toBe(104n);
      expect(claimArray[1]![0]).toBe(0n);
    });
  });

  describe("modInverse", () => {
    it("should compute modular inverse correctly", () => {
      const a = 3n;
      const m = 11n;
      const inv = modInverse(a, m);
      expect((a * inv) % m).toBe(1n);
    });

    it("should work with P-256 scalar field", () => {
      const a = 12345678901234567890n;
      const inv = modInverse(a, P256_SCALAR_ORDER);
      expect((a * inv) % P256_SCALAR_ORDER).toBe(1n);
    });
  });
});

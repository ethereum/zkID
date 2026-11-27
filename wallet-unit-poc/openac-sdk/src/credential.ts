import { sha256 } from "@noble/hashes/sha2";
import {
  base64Decode,
  base64urlToBase64,
  base64urlEncode,
  utf8Decode,
} from "./utils.js";
import { InputError } from "./errors.js";
import type { DisclosedClaim, EcdsaPublicKey, JsonValue } from "./types.js";

export class Credential {
  readonly header: Record<string, unknown>;
  readonly payload: Record<string, unknown>;
  readonly signature: Uint8Array;
  readonly token: string;
  readonly claims: DisclosedClaim[];
  readonly b64Header: string;
  readonly b64Payload: string;
  readonly b64Signature: string;

  private constructor(
    token: string,
    header: Record<string, unknown>,
    payload: Record<string, unknown>,
    signature: Uint8Array,
    claims: DisclosedClaim[],
    b64Header: string,
    b64Payload: string,
    b64Signature: string,
  ) {
    this.token = token;
    this.header = header;
    this.payload = payload;
    this.signature = signature;
    this.claims = claims;
    this.b64Header = b64Header;
    this.b64Payload = b64Payload;
    this.b64Signature = b64Signature;
  }

  static parse(
    jwt: string,
    disclosures: string[],
    opts: CredentialProfileOptions = {},
  ): Credential {
    const parts = jwt.split(".");
    if (parts.length !== 3) {
      throw new InputError(
        "INVALID_JWT",
        `Invalid JWT format: expected 3 parts, got ${parts.length}`,
      );
    }

    const [b64Header, b64Payload, b64Signature] = parts as [
      string,
      string,
      string,
    ];

    let header: Record<string, unknown>;
    let payload: Record<string, unknown>;

    try {
      header = JSON.parse(utf8Decode(base64Decode(b64Header)));
    } catch (e) {
      throw new InputError("INVALID_JWT", "Failed to decode JWT header", e);
    }

    try {
      payload = JSON.parse(utf8Decode(base64Decode(b64Payload)));
    } catch (e) {
      throw new InputError("INVALID_JWT", "Failed to decode JWT payload", e);
    }

    validateProfile(header, payload, opts);

    const signature = base64Decode(b64Signature);

    const claims: DisclosedClaim[] = disclosures.map((raw, index) => {
      return parseDisclosure(raw, index);
    });
    const claimNames = new Set<string>();
    for (const claim of claims) {
      if (claimNames.has(claim.name)) {
        throw new InputError(
          "AMBIGUOUS_PAYLOAD",
          `Credential discloses claim "${claim.name}" more than once; duplicate claim names are ambiguous`,
        );
      }
      claimNames.add(claim.name);
    }

    return new Credential(
      jwt,
      header,
      payload,
      signature,
      claims,
      b64Header,
      b64Payload,
      b64Signature,
    );
  }

  findBirthdayClaim(): number | null {
    const birthdayKeys = [
      "roc_birthday",
      "birthdate",
      "birthday",
      "date_of_birth",
    ];

    for (const claim of this.claims) {
      if (birthdayKeys.includes(claim.name)) {
        return claim.index;
      }
    }

    return null;
  }

  get deviceBindingKey(): EcdsaPublicKey | null {
    const cnf = this.payload.cnf as { jwk?: EcdsaPublicKey } | undefined;
    if (!cnf?.jwk) return null;

    const jwk = cnf.jwk;
    if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.x || !jwk.y) {
      return null;
    }

    return jwk;
  }

  get decodedPayload(): string {
    return utf8Decode(base64Decode(this.b64Payload));
  }

  get sdDigests(): string[] {
    const vc = this.payload.vc as
      | { credentialSubject?: { _sd?: string[] } }
      | undefined;
    return vc?.credentialSubject?._sd ?? [];
  }

  get disclosureHashes(): string[] {
    return this.claims.map((c) => c.digest);
  }
}

export interface CredentialProfileOptions {
  /**
   * Current time (seconds since epoch) for the holder-side exp/nbf check.
   * Defaults to the local clock. This check is not part of the proof, so a
   * relying party must check exp/nbf itself.
   */
  now?: number;
  /** Tolerated clock skew in seconds for nbf/exp. Default 60. */
  clockSkewSec?: number;
  /** Reject credentials with no `exp`. Default false (exp is optional in SD-JWT VC). */
  requireExpiry?: boolean;
}

// The proving path only ever verifies ES256 over the compact bytes and only ever
// computes SHA-256 disclosure digests, so anything else is out of profile. This
// runs before signature verification and before any circuit input is built, so a
// wrong-profile or stale token can never reach a proof.
function validateProfile(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  opts: CredentialProfileOptions,
): void {
  const fail = (msg: string): never => {
    throw new InputError("INVALID_JWT", msg);
  };

  if (header.alg !== "ES256")
    fail(`Unsupported JOSE alg: ${String(header.alg)} (expected ES256)`);
  if (header.typ !== undefined && !SUPPORTED_TYP.includes(String(header.typ))) {
    fail(`Unsupported JOSE typ: ${String(header.typ)}`);
  }
  if (header.crit !== undefined) fail("Unsupported JOSE crit header");

  const sdAlg = (
    payload.vc as { credentialSubject?: { _sd_alg?: unknown } } | undefined
  )?.credentialSubject?._sd_alg;
  if (sdAlg !== undefined && sdAlg !== "sha-256") {
    fail(`Unsupported SD-JWT _sd_alg: ${String(sdAlg)} (expected sha-256)`);
  }

  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const skew = opts.clockSkewSec ?? 60;

  const exp = payload.exp;
  if (exp === undefined) {
    if (opts.requireExpiry) fail("Credential has no exp claim");
  } else if (typeof exp !== "number" || now - skew >= exp) {
    fail(`Credential expired (exp=${String(exp)}, now=${now})`);
  }

  const nbf = payload.nbf;
  if (nbf !== undefined && (typeof nbf !== "number" || now + skew < nbf)) {
    fail(`Credential not yet valid (nbf=${String(nbf)}, now=${now})`);
  }
}

const SUPPORTED_TYP = ["vc+sd-jwt", "dc+sd-jwt", "JWT"];

// SD-JWT disclosure: base64url(JSON([salt, claim_name, claim_value]))
function parseDisclosure(raw: string, index: number): DisclosedClaim {
  let decoded: string;
  try {
    const b64 = base64urlToBase64(raw);
    decoded = utf8Decode(base64Decode(b64));
  } catch (e) {
    throw new InputError(
      "MISSING_DISCLOSURE",
      `Failed to decode disclosure at index ${index}`,
      e,
    );
  }

  // The claim extractors locate each field by counting raw 0x22 bytes and
  // reject any backslash, so a disclosure carrying a JSON escape cannot be
  // proven. Fail here with a clear error rather than deep inside witness
  // generation. Raw UTF-8 is fine (continuation bytes are 0x80-0xBF); only
  // escape sequences such as \" or \uXXXX are refused.
  if (decoded.includes("\\")) {
    throw new InputError(
      "INVALID_ENCODING",
      `Disclosure at index ${index} contains a JSON escape sequence; ` +
        `the credential circuits only accept escape-free disclosures`,
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(decoded);
  } catch (e) {
    throw new InputError(
      "MISSING_DISCLOSURE",
      `Failed to parse disclosure JSON at index ${index}`,
      e,
    );
  }

  if (
    !Array.isArray(parsed) ||
    parsed.length !== 3 ||
    typeof parsed[0] !== "string" ||
    typeof parsed[1] !== "string"
  ) {
    throw new InputError(
      "MISSING_DISCLOSURE",
      `Invalid disclosure format at index ${index}: expected [string salt, string name, value]`,
    );
  }

  const [salt, name, value] = parsed as [string, string, JsonValue];

  const digestBytes = sha256(new TextEncoder().encode(raw));
  const digest = base64urlEncode(digestBytes);

  return {
    index,
    salt,
    name,
    value,
    raw,
    digest,
  };
}

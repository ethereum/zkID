/**
 * Builds synthetic TBSCertificates signed by a throwaway test CA, and the
 * matching CertChainRSA256 inputs. Lets tests vary one DER field at a time
 * (validity, serial length, name lengths, key type) without real certificates.
 */
import {
  constants as cryptoConstants,
  generateKeyPairSync,
  sign as cryptoSign,
  type KeyObject,
} from "node:crypto";
import { sha256Pad } from "@zk-email/helpers/dist/shaHash";
import {
  bigIntToChunkedBytes,
  bytesToBigInt,
} from "@zk-email/helpers/dist/binaryFormat";

const MAX_MESSAGE_LENGTH = 1536;
const N_BITS = 121;
const K_LIMBS = 17;
const SMT_DEPTH = 128;

export function tlv(tag: number, content: Uint8Array): Buffer {
  const len = content.length;
  let header: number[];
  if (len < 0x80) header = [tag, len];
  else if (len < 0x100) header = [tag, 0x81, len];
  else header = [tag, 0x82, len >> 8, len & 0xff];
  return Buffer.concat([Buffer.from(header), content]);
}

const OID_OU = [0x55, 0x04, 0x0b];
const OID_CN = [0x55, 0x04, 0x03];
const OID_C = [0x55, 0x04, 0x06];

function rdn(oid: number[], stringTag: number, value: string): Buffer {
  return tlv(
    0x31,
    tlv(
      0x30,
      Buffer.concat([
        tlv(0x06, Buffer.from(oid)),
        tlv(stringTag, Buffer.from(value, "utf8")),
      ])
    )
  );
}

/** Name with C=TW, one filler OU per entry of `ouLengths` (bytes), and a CN. */
export function name(commonName: string, ouLengths: number[] = []): Buffer {
  const parts = [rdn(OID_C, 0x13, "TW")];
  for (const length of ouLengths) {
    parts.push(rdn(OID_OU, 0x0c, "x".repeat(length)));
  }
  parts.push(rdn(OID_CN, 0x0c, commonName));
  return tlv(0x30, Buffer.concat(parts));
}

/** 13 chars (`YYMMDDHHMMSSZ`) encode as UTCTime, 15 as GeneralizedTime. */
function time(value: string): Buffer {
  const tag = value.length === 13 ? 0x17 : 0x18;
  return tlv(tag, Buffer.from(value, "ascii"));
}

const SIG_ALG_SHA256_RSA = Buffer.from(
  "300d06092a864886f70d01010b0500",
  "hex"
);

// The first three extensions of a MOICA end-entity certificate, in MOICA's
// order: authorityKeyIdentifier (keyIdentifier only), subjectKeyIdentifier,
// keyUsage (critical).
export const AUTHORITY_KEY_ID = Buffer.concat([
  Buffer.from("301f0603551d23041830168014", "hex"),
  Buffer.alloc(20, 0xa1),
]);
export const SUBJECT_KEY_ID = Buffer.concat([
  Buffer.from("301d0603551d0e04160414", "hex"),
  Buffer.alloc(20, 0xb2),
]);

/** keyUsage extension (critical) with the given BIT STRING bytes. */
export function keyUsage(bits: string): Buffer {
  const value = tlv(0x03, Buffer.from(bits, "hex"));
  return tlv(
    0x30,
    Buffer.concat([
      Buffer.from("0603551d0f0101ff", "hex"),
      tlv(0x04, value),
    ])
  );
}

/** `07 80`: 7 unused bits, digitalSignature only — MOICA's signing certificate. */
export const KEY_USAGE_SIGNING = keyUsage("0780");
/** `04 30`: keyEncipherment + dataEncipherment — MOICA's encryption certificate. */
export const KEY_USAGE_ENCRYPTION = keyUsage("0430");

/** `[3] EXPLICIT Extensions` holding `list`. */
function extensions(list: Buffer[]): Buffer {
  return tlv(0xa3, tlv(0x30, Buffer.concat(list)));
}

/** An extension with a private-arc OID wrapping `value` in its OCTET STRING. */
export function opaqueExtension(value: Uint8Array): Buffer {
  // 1.3.6.1.4.1.99999.1
  const oid = Buffer.from("06092b0601040186 8d1f01".replace(/ /g, ""), "hex");
  return tlv(0x30, Buffer.concat([oid, tlv(0x04, value)]));
}

export interface TestCa {
  privateKey: KeyObject;
  modulusLimbs: string[];
}

export function makeTestCa(): TestCa {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicExponent: 65537,
  });
  const jwk = publicKey.export({ format: "jwk" });
  const modulus = bytesToBigInt(Buffer.from(jwk.n as string, "base64url"));
  return {
    privateKey,
    modulusLimbs: bigIntToChunkedBytes(modulus, N_BITS, K_LIMBS),
  };
}

export function makeUserSpki(modulusLength = 2048): Buffer {
  const { publicKey } = generateKeyPairSync("rsa", {
    modulusLength,
    publicExponent: 65537,
  });
  return publicKey.export({ format: "der", type: "spki" });
}

export interface TbsOptions {
  /** Include the `[0] EXPLICIT` v3 version block. Default true. */
  version?: boolean;
  serial?: Uint8Array;
  issuer?: Buffer;
  notBefore?: string;
  notAfter?: string;
  subject?: Buffer;
  spki: Buffer;
  /** Extensions to add after keyUsage. */
  extraExtensions?: Buffer[];
  /** Replaces the leading extensions (default: AKI, SKI, keyUsage signing). */
  leadingExtensions?: Buffer[];
}

export function buildTbs(opts: TbsOptions): Buffer {
  const parts: Buffer[] = [];
  if (opts.version !== false) {
    parts.push(Buffer.from("a003020102", "hex"));
  }
  parts.push(
    tlv(0x02, opts.serial ?? Buffer.from("1234567890abcdef1234567890abcdef", "hex")),
    SIG_ALG_SHA256_RSA,
    opts.issuer ?? name("Test CA"),
    tlv(
      0x30,
      Buffer.concat([
        time(opts.notBefore ?? "260101000000Z"),
        time(opts.notAfter ?? "310101155959Z"),
      ])
    ),
    opts.subject ?? name("Test User"),
    opts.spki,
    extensions([
      ...(opts.leadingExtensions ?? [
        AUTHORITY_KEY_ID,
        SUBJECT_KEY_ID,
        KEY_USAGE_SIGNING,
      ]),
      // MOICA certificates carry several hundred bytes of further extensions
      // (policies, CRL and AIA URLs); pad so the Extensions length is in the
      // two-byte long form the circuit expects.
      opaqueExtension(Buffer.alloc(200, 0xcc)),
      ...(opts.extraExtensions ?? []),
    ])
  );
  return tlv(0x30, Buffer.concat(parts));
}

/** CertChainRSA256 inputs for `tbs`, signed by `ca`, against an empty SMT. */
export function chainInputs(
  ca: TestCa,
  tbs: Buffer,
  currentTime: bigint
): Record<string, any> {
  const [padded, paddedLength] = sha256Pad(
    new Uint8Array(tbs),
    MAX_MESSAGE_LENGTH
  );
  const signature = cryptoSign("sha256", tbs, {
    key: ca.privateKey,
    padding: cryptoConstants.RSA_PKCS1_PADDING,
  });
  const serialLength = tbs[tbs[4] === 0xa0 ? 10 : 5];
  const serialStart = tbs[4] === 0xa0 ? 11 : 6;
  const serial = bytesToBigInt(tbs.subarray(serialStart, serialStart + serialLength));
  return {
    issuerTbs: Array.from(padded).map((b) => BigInt(b)),
    issuerTbsLength: BigInt(paddedLength),
    actualIssuerTbsLength: BigInt(tbs.length),
    issuerRsaModulus: ca.modulusLimbs.map((l) => BigInt(l)),
    issuerRsaSignature: bigIntToChunkedBytes(
      bytesToBigInt(signature),
      N_BITS,
      K_LIMBS
    ).map((l) => BigInt(l)),
    smtRoot: 0n,
    serialNumber: serial,
    smtSiblings: Array(SMT_DEPTH).fill(0n),
    smtOldKey: 0n,
    smtOldValue: 0n,
    smtIsOld0: 1n,
    currentTime,
    pkBlind: 12345n,
  };
}

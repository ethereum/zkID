import { strict as assert } from "assert";
import type { WitnessTester } from "circomkit";
import { p256 } from "@noble/curves/p256";
import { Field } from "@noble/curves/abstract/modular";
import { sha256Pad } from "@zk-email/helpers";
import {
  buildJsonLdPrepareInputs,
  JSONLD_BASE,
  JSONLD_DEFAULT_PARAMS,
  JSONLD_FORMAT,
  type JsonLdClaimRequest,
  type JsonLdParams,
} from "../../src/jsonld/build-inputs.ts";
import {
  FIXTURE_NQUADS,
  FIXTURE_PROOF_NQUADS,
  loadTestIssuer,
  proofHashOf,
  signJsonLd,
} from "../../src/jsonld/test-fixture.ts";

export { JSONLD_FORMAT, JSONLD_BASE, JSONLD_DEFAULT_PARAMS };

export const PROD_PARAMS = [2240, 2, 128, 31, 64, 252] as const;

export const BOTH_CLAIMS: JsonLdClaimRequest[] = [
  { name: "dateOfBirth", format: JSONLD_FORMAT.isoDate },
  { name: "nationality", format: JSONLD_FORMAT.digest64 },
];

const Fn = Field(BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"));
const UTF8 = new TextEncoder();

export const issuer = loadTestIssuer();

export type JsonLdInputs = ReturnType<typeof buildJsonLdPrepareInputs>["inputs"];

export function buildFixture(
  claims: JsonLdClaimRequest[] = BOTH_CLAIMS,
  params?: Partial<JsonLdParams>,
  nquads: string = FIXTURE_NQUADS(),
) {
  const proofHash = proofHashOf(FIXTURE_PROOF_NQUADS());
  const built = buildJsonLdPrepareInputs({
    nquads,
    proofHash,
    signature: signJsonLd(nquads, proofHash),
    issuerPublicKey: { x: issuer.x, y: issuer.y },
    base: JSONLD_BASE,
    claims,
    params,
  });
  return { nquads, proofHash, ...built };
}

/** Byte offset of the first occurrence of `needle` in `doc`. */
export function offsetOf(doc: string, needle: string): number {
  const i = doc.indexOf(needle);
  if (i < 0) throw new Error(`not in document: ${needle}`);
  return UTF8.encode(doc.slice(0, i)).length;
}

const CS_MARK = " <https://www.w3.org/2018/credentials#credentialSubject> <";

function decodeBytes(arr: bigint[], len: bigint): string {
  return String.fromCharCode(...arr.slice(0, Number(len)).map(Number));
}

/**
 * Swaps in a different document, re-signed by the test issuer so the signature
 * stays valid and only the structural checks are under test. csPos, the deviceKey
 * line and each active claim line are re-located in the new document by name, so
 * a test only patches what it means to break. `opts.subject` is for documents that
 * change the subject IRI.
 */
export function withDoc(
  inputs: JsonLdInputs,
  nquads: string,
  proofHash: Uint8Array,
  opts: { subject?: string; maxDocLen?: number } = {},
): JsonLdInputs {
  const bytes = UTF8.encode(nquads);
  const [padded, paddedLen] = sha256Pad(bytes, opts.maxDocLen ?? 2240);
  const { r, s } = signJsonLd(nquads, proofHash);
  const subject = opts.subject ?? decodeBytes(inputs.subject, inputs.subjectLength);
  const lineStart = (name: string) => offsetOf(nquads, `<${subject}> <${JSONLD_BASE}${name}> `);
  return {
    ...inputs,
    doc: Array.from(padded, (b) => BigInt(b)),
    docLength: BigInt(paddedLen),
    sig_r: r,
    sig_s_inverse: Fn.inv(s),
    csPos: BigInt(offsetOf(nquads, CS_MARK)),
    deviceKeyLinePos: BigInt(lineStart("deviceKey")),
    linePos: inputs.linePos.map((p, i) =>
      inputs.claimFlags[i] === 1n ? BigInt(lineStart(decodeBytes(inputs.names[i], inputs.nameLengths[i]))) : p,
    ),
  };
}

/**
 * Witness generation must throw, and the innermost template of the failing call
 * stack must match `template`. The wasm calculator keeps the frames of earlier
 * failures in the same instance, so only the last stack is read: each stack ends
 * at the main template, `main`.
 */
export async function expectFailIn(
  circuit: WitnessTester<any, any>,
  inputs: unknown,
  template: RegExp,
  main = "JSONLD",
): Promise<void> {
  let msg = "";
  try {
    await circuit.calculateWitness(inputs as any);
  } catch (e) {
    msg = String(e);
  }
  assert.ok(msg, "witness generation unexpectedly succeeded");
  const frames = [...msg.matchAll(/Error in template ([A-Za-z0-9]+)_\d+/g)].map((m) => m[1]);
  const ends = frames.flatMap((f, i) => (f === main ? [i] : []));
  assert.ok(ends.length > 0, `no ${main} frame in\n${msg}`);
  const last = ends[ends.length - 1];
  const stackStart = ends.length > 1 ? ends[ends.length - 2] + 1 : 0;
  const innermost = frames[stackStart];
  assert.ok(stackStart <= last);
  assert.match(innermost, template, `failed in ${innermost}, expected ${template}\n${msg}`);
}

export function bytesPadded(s: string, len: number): bigint[] {
  const out = new Array<bigint>(len).fill(0n);
  UTF8.encode(s).forEach((b, i) => (out[i] = BigInt(b)));
  return out;
}

export function otherIssuerKey(): { x: bigint; y: bigint } {
  const pub = p256.getPublicKey(p256.utils.randomPrivateKey(), false);
  const big = (b: Uint8Array) => b.reduce((n, v) => (n << 8n) | BigInt(v), 0n);
  return { x: big(pub.slice(1, 33)), y: big(pub.slice(33, 65)) };
}

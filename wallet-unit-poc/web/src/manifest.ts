// Asset URLs for proving keys, witness wasm, and SMT snapshots, plus a
// hydrator that pulls per-asset SHA-256 digests from the GitHub Release
// API. We verify those digests against the **compressed** bytes during
// download — gzip determinism transitively pins the decompressed payload,
// so a separate manifest.json isn't needed.

import type { SmtIssuer } from "./smt-client";

export type CircuitKind =
  | "certChainRS2048"
  | "certChainRS4096"
  | "userSigRS2048";

export interface CircuitManifest {
  kind: CircuitKind;
  numPublic: number;
  /** /keys/<asset>.gz in dev (proxy), absolute URL in prod. */
  pkUrl: string;
  witnessWasmUrl: string;
}

export interface SmtAssetManifest {
  issuer: SmtIssuer;
  /** /smt-snapshot/<issuer>-tree-snapshot.bin.gz in dev. */
  snapshotUrl: string;
}

export const CIRCUITS: Record<CircuitKind, CircuitManifest> = {
  certChainRS2048: {
    kind: "certChainRS2048",
    numPublic: 20,
    pkUrl: "/keys/cert_chain_rs2048_proving.key.gz",
    witnessWasmUrl: "/keys/certChainRS2048.wasm.gz",
  },
  certChainRS4096: {
    kind: "certChainRS4096",
    numPublic: 37,
    pkUrl: "/keys/cert_chain_rs4096_proving.key.gz",
    witnessWasmUrl: "/keys/certChainRS4096.wasm.gz",
  },
  userSigRS2048: {
    kind: "userSigRS2048",
    numPublic: 4,
    pkUrl: "/keys/user_sig_rs2048_proving.key.gz",
    witnessWasmUrl: "/keys/userSigRS2048.wasm.gz",
  },
};

export const SMT_SNAPSHOTS: Record<SmtIssuer, SmtAssetManifest> = {
  g2: { issuer: "g2", snapshotUrl: "/smt-snapshot/g2-tree-snapshot.bin.gz" },
  g3: { issuer: "g3", snapshotUrl: "/smt-snapshot/g3-tree-snapshot.bin.gz" },
};

export const SMT_WASM = { url: "/smt-snapshot/smt.wasm" };
export const SMT_WASM_EXEC = { url: "/smt-snapshot/wasm_exec.js" };

const KEYS_RELEASE_API =
  "https://api.github.com/repos/zkmopro/zkID/releases/tags/latest";
const SMT_RELEASE_API =
  "https://api.github.com/repos/privacy-ethereum/moica-revocation-smt/releases/tags/snapshot-latest";

export type DigestMap = Record<string, string>;

export interface ReleaseDigests {
  keys: DigestMap;
  smt: DigestMap;
}

export type ManifestErrorCode =
  | "rate_limited"
  | "unreachable"
  | "malformed"
  | "missing_asset";

export class ManifestError extends Error {
  readonly code: ManifestErrorCode;
  constructor(
    message: string,
    code: ManifestErrorCode,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = "ManifestError";
    this.code = code;
  }
}

const HEX_64 = /^[0-9a-f]{64}$/;
const SHA_PREFIX = /^sha256:([0-9a-f]{64})$/;

export function basename(url: string): string {
  const q = url.indexOf("?");
  const clean = q === -1 ? url : url.slice(0, q);
  const slash = clean.lastIndexOf("/");
  return slash === -1 ? clean : clean.slice(slash + 1);
}

async function fetchReleaseJson(url: string): Promise<unknown> {
  let res: Response;
  try {
    res = await fetch(url, {
      headers: { Accept: "application/vnd.github+json" },
    });
  } catch (err) {
    throw new ManifestError(`cannot reach ${url}`, "unreachable", { cause: err });
  }
  if (res.status === 403 || res.status === 429) {
    // GitHub returns 403 with X-RateLimit-Remaining: 0 (or 429) when the
    // unauthenticated 60/h budget is exhausted — common behind shared NAT.
    throw new ManifestError(
      `${url} rate-limited (${res.status} ${res.statusText})`,
      "rate_limited",
    );
  }
  if (!res.ok) {
    throw new ManifestError(
      `${url} returned ${res.status} ${res.statusText}`,
      "unreachable",
    );
  }
  try {
    return await res.json();
  } catch (err) {
    throw new ManifestError(`malformed JSON from ${url}`, "malformed", {
      cause: err,
    });
  }
}

function parseAssetDigests(url: string, body: unknown): DigestMap {
  if (!body || typeof body !== "object") {
    throw new ManifestError(
      `response from ${url} is not an object`,
      "malformed",
    );
  }
  const assets = (body as { assets?: unknown }).assets;
  if (!Array.isArray(assets)) {
    throw new ManifestError(
      `response from ${url} has no \`assets\` array`,
      "malformed",
    );
  }
  const out: DigestMap = {};
  for (const a of assets) {
    if (!a || typeof a !== "object") continue;
    const name = (a as { name?: unknown }).name;
    const digest = (a as { digest?: unknown }).digest;
    if (typeof name !== "string" || typeof digest !== "string") continue;
    const m = SHA_PREFIX.exec(digest);
    if (!m) continue;
    out[name] = m[1];
  }
  return out;
}

export async function fetchReleaseDigests(): Promise<ReleaseDigests> {
  const [keysBody, smtBody] = await Promise.all([
    fetchReleaseJson(KEYS_RELEASE_API),
    fetchReleaseJson(SMT_RELEASE_API),
  ]);
  return {
    keys: parseAssetDigests(KEYS_RELEASE_API, keysBody),
    smt: parseAssetDigests(SMT_RELEASE_API, smtBody),
  };
}

export function requireDigest(map: DigestMap, filename: string): string {
  const sha = map[filename];
  if (!sha || !HEX_64.test(sha)) {
    throw new ManifestError(
      `no sha256 digest published for ${filename}`,
      "missing_asset",
    );
  }
  return sha;
}

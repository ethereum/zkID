import { IssuerRegistry, sha256Scheme as issuerSha256Scheme } from "@coordination-network/issuer-registry";
import { RevocationRegistry, sha256Scheme as revocationSha256Scheme } from "@coordination-network/revocation-registry";

type BigNumberish = bigint | number | string;

export interface RegistryClientOptions {
  /** Bearer token: the owner token of the registry being written. */
  token?: string;
  fetch?: typeof globalThis.fetch;
}

export interface IssuerRegistryInfo {
  root: bigint;
  depth: number;
  size: number;
  maxDepth: number;
  rootDuration: number;
  /** Every leaf in index order, `0` for a removed issuer. */
  leaves: bigint[];
}

export interface RevocationRegistryInfo {
  root: bigint;
  depth: number;
  size: number;
  rootDuration: number;
  /** Every physical slot in index order, sentinel and tombstones included. */
  leaves: { value: bigint; nextValue: bigint }[];
}

export class RegistryClientError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "RegistryClientError";
  }
}

/**
 * Client for the off-chain registry server.
 *
 * Holders call {@link syncIssuerRegistry} and {@link syncRevocationRegistry} and
 * prove against the returned trees. They download the whole tree, so the
 * server never learns which issuer or which revocation commitment a holder
 * cares about. Verifiers pass {@link isValidIssuerRoot} and
 * {@link isValidRevocationRoot} to the SDK's `verify`.
 */
export class RegistryClient {
  private readonly baseUrl: string;
  private readonly token: string | undefined;
  private readonly fetchImpl: typeof globalThis.fetch;

  constructor(baseUrl: string, options: RegistryClientOptions = {}) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.token = options.token;
    this.fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  // Holder and verifier reads.

  async getIssuerRegistry(): Promise<IssuerRegistryInfo> {
    const body = await this.request("GET", "/issuer");
    return {
      root: BigInt(body.root as string),
      depth: body.depth as number,
      size: body.size as number,
      maxDepth: body.maxDepth as number,
      rootDuration: body.rootDuration as number,
      leaves: (body.leaves as string[]).map((leaf) => BigInt(leaf)),
    };
  }

  /**
   * Rebuilds the issuer tree from the server's leaves and checks it reproduces
   * the root served with them. Use the result's `generateProof(issuerCommitment)`
   * as the SDK's `issuerProof`.
   */
  async syncIssuerRegistry(): Promise<IssuerRegistry> {
    const info = await this.getIssuerRegistry();
    const registry = IssuerRegistry.fromLeaves(info.leaves, issuerSha256Scheme);
    if (registry.root !== info.root) {
      throw new RegistryClientError(0, "ROOT_MISMATCH", "The issuer leaves do not reproduce the served root");
    }
    return registry;
  }

  async getIssuerRoot(): Promise<bigint> {
    return BigInt((await this.request("GET", "/issuer/root")).root as string);
  }

  /** An SDK `IssuerRootCheck`: `verify(..., { isValidIssuerRoot: client.isValidIssuerRoot })`. */
  readonly isValidIssuerRoot = async (root: bigint): Promise<boolean> => {
    return (await this.request("GET", `/issuer/roots/${uint(root)}`)).valid === true;
  };

  async isIssuer(commitment: BigNumberish): Promise<boolean> {
    return (await this.request("GET", `/issuer/commitments/${uint(commitment)}`)).isIssuer === true;
  }

  async getRevocationRegistry(): Promise<RevocationRegistryInfo> {
    const body = await this.request("GET", "/revocation");
    return {
      root: BigInt(body.root as string),
      depth: body.depth as number,
      size: body.size as number,
      rootDuration: body.rootDuration as number,
      leaves: (body.leaves as { value: string; nextValue: string }[]).map((slot) => ({
        value: BigInt(slot.value),
        nextValue: BigInt(slot.nextValue),
      })),
    };
  }

  /**
   * Rebuilds the revocation tree from the server's slots and checks it
   * reproduces the root served with them. Pass the result as the SDK's
   * `revocation.registry`.
   */
  async syncRevocationRegistry(): Promise<RevocationRegistry> {
    const info = await this.getRevocationRegistry();
    const registry =
      info.leaves.length === 0
        ? new RevocationRegistry([], revocationSha256Scheme)
        : RevocationRegistry.fromLeaves(info.leaves, revocationSha256Scheme);
    if (registry.root !== info.root) {
      throw new RegistryClientError(0, "ROOT_MISMATCH", "The revocation slots do not reproduce the served root");
    }
    return registry;
  }

  async getRevocationRoot(): Promise<bigint> {
    return BigInt((await this.request("GET", "/revocation/root")).root as string);
  }

  /** An SDK `RevocationRootCheck`: `verify(..., { isValidRevocationRoot: client.isValidRevocationRoot })`. */
  readonly isValidRevocationRoot = async (root: bigint): Promise<boolean> => {
    return (await this.request("GET", `/revocation/roots/${uint(root)}`)).valid === true;
  };

  /**
   * Whether a commitment is revoked. A holder asking this reveals its
   * commitment to the server, so holders should sync the tree instead.
   */
  async isRevoked(commitment: BigNumberish): Promise<boolean> {
    return (await this.request("GET", `/revocation/commitments/${uint(commitment)}`)).isRevoked === true;
  }

  // Issuer registry owner writes. Each returns the new root.

  async addIssuers(commitments: BigNumberish[]): Promise<bigint> {
    return this.root("POST", "/issuer/commitments", { commitments: commitments.map(uint) });
  }

  async removeIssuer(commitment: BigNumberish): Promise<bigint> {
    return this.root("DELETE", `/issuer/commitments/${uint(commitment)}`);
  }

  async updateIssuerCommitment(oldCommitment: BigNumberish, newCommitment: BigNumberish): Promise<bigint> {
    return this.root("PUT", `/issuer/commitments/${uint(oldCommitment)}`, { newCommitment: uint(newCommitment) });
  }

  async updateIssuerRootDuration(rootDuration: number): Promise<void> {
    await this.request("PUT", "/issuer/root-duration", { rootDuration });
  }

  /** Rejects every superseded issuer root. Call after removing a compromised issuer. */
  async expireIssuerRoots(): Promise<void> {
    await this.request("POST", "/issuer/expire-roots");
  }

  // Revocation registry owner writes. Each commitment write returns the new root.

  async revoke(commitments: BigNumberish | BigNumberish[]): Promise<bigint> {
    const list = Array.isArray(commitments) ? commitments : [commitments];
    return this.root("POST", "/revocation/commitments", { commitments: list.map(uint) });
  }

  async unrevoke(commitment: BigNumberish): Promise<bigint> {
    return this.root("DELETE", `/revocation/commitments/${uint(commitment)}`);
  }

  async updateRevocationCommitment(oldCommitment: BigNumberish, newCommitment: BigNumberish): Promise<bigint> {
    return this.root("PUT", `/revocation/commitments/${uint(oldCommitment)}`, {
      newCommitment: uint(newCommitment),
    });
  }

  async updateRevocationRootDuration(rootDuration: number): Promise<void> {
    await this.request("PUT", "/revocation/root-duration", { rootDuration });
  }

  private async root(method: string, path: string, body?: unknown): Promise<bigint> {
    return BigInt((await this.request(method, path, body)).root as string);
  }

  private async request(method: string, path: string, body?: unknown): Promise<Record<string, unknown>> {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (this.token !== undefined) headers.Authorization = `Bearer ${this.token}`;
    const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await response.text();
    let parsed: Record<string, unknown> = {};
    try {
      parsed = text ? (JSON.parse(text) as Record<string, unknown>) : {};
    } catch {
      // A non-JSON body (e.g. from a proxy) is reported below by status.
    }
    if (!response.ok) {
      throw new RegistryClientError(
        response.status,
        typeof parsed.error === "string" ? parsed.error : "HTTP_ERROR",
        typeof parsed.message === "string" ? parsed.message : `${method} ${path} failed with ${response.status}`,
      );
    }
    return parsed;
  }
}

function uint(value: BigNumberish): string {
  const parsed = BigInt(value);
  if (parsed < 0n) throw new RangeError("Registry values are unsigned");
  return parsed.toString();
}

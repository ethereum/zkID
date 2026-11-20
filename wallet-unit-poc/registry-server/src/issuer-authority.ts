import {
  IssuerRegistry,
  sha256Scheme,
  toCommitment,
  type BigNumberish,
  type IssuerProof,
} from "@coordination-network/issuer-registry";

import { RegistryError, toRegistryError } from "./errors.js";
import { DEFAULT_ROOT_DURATION, RootHistory, systemClock, type Clock, type RootHistoryState } from "./root-history.js";

/** Show `maxIssuerDepth`: at most 2^8 = 256 issuers stay provable. */
export const DEFAULT_ISSUER_MAX_DEPTH = 8;

export interface IssuerAuthorityOptions {
  /** Deepest tree the Show circuit can prove membership in. */
  maxDepth?: number;
  /** Seconds a superseded root stays valid. */
  rootDuration?: number;
  clock?: Clock;
}

export interface IssuerAuthorityState {
  version: 1;
  maxDepth: number;
  /** `IssuerRegistry.export()` output. */
  tree: string;
  history: RootHistoryState;
}

/**
 * The approved-issuer set, held off chain: a SHA-256 LeanIMT of issuer
 * commitments `sha256(be32(pubKeyX) || be32(pubKeyY))`. Behaves like
 * `OpenACIssuerRegistry` over `Sha256IssuerRegistry`: the same tree and roots,
 * a depth cap, a root history with `rootDuration`, and `expireRoots`.
 *
 * Every write is all or nothing: on any failure the tree is restored.
 */
export class IssuerRegistryAuthority {
  readonly maxDepth: number;
  private tree: IssuerRegistry;
  private history: RootHistory;
  private readonly clock: Clock;

  constructor(options: IssuerAuthorityOptions = {}) {
    this.maxDepth = checkMaxDepth(options.maxDepth ?? DEFAULT_ISSUER_MAX_DEPTH);
    this.tree = new IssuerRegistry([], sha256Scheme);
    this.history = new RootHistory(options.rootDuration ?? DEFAULT_ROOT_DURATION);
    this.clock = options.clock ?? systemClock;
  }

  /** `0` while empty, and never accepted by {@link isValidRoot}. */
  get root(): bigint {
    return this.tree.root;
  }

  get depth(): number {
    return this.tree.depth;
  }

  /** The number of leaves, removed issuers included. */
  get size(): number {
    return this.tree.size;
  }

  /** Every leaf in index order, `0` for a removed issuer. What holders rebuild from, like `getLeaf` on chain. */
  get leaves(): bigint[] {
    return this.tree.leaves;
  }

  get rootDuration(): number {
    return this.history.rootDuration;
  }

  isIssuer(commitment: BigNumberish): boolean {
    return this.tree.isIssuer(commitment);
  }

  /** The leaf index of an approved commitment, or `-1`. */
  indexOf(commitment: BigNumberish): number {
    return this.tree.indexOf(commitment);
  }

  addIssuer(commitment: BigNumberish): bigint {
    return this.write((tree) => tree.addIssuer(commitment));
  }

  addIssuers(commitments: BigNumberish[]): bigint {
    if (commitments.length === 0) throw new RegistryError("INVALID_INPUT", "No issuer commitments");
    return this.write((tree) => tree.addIssuers(commitments));
  }

  /** Zeroes the issuer's leaf. Call {@link expireRoots} too when the issuer's key is compromised. */
  removeIssuer(commitment: BigNumberish): bigint {
    return this.write((tree) => tree.removeIssuer(commitment));
  }

  updateIssuerCommitment(oldCommitment: BigNumberish, newCommitment: BigNumberish): bigint {
    return this.write((tree) => tree.updateIssuerCommitment(oldCommitment, newCommitment));
  }

  updateRootDuration(rootDuration: number): void {
    this.history.rootDuration = rootDuration;
  }

  /** Rejects every superseded root; only the current one stays valid. */
  expireRoots(): void {
    this.history.expireAll(this.tree.root, this.clock());
  }

  /**
   * Whether a presentation's issuer root is accepted: the current non-empty
   * root, or one superseded less than `rootDuration` seconds ago and after the
   * last {@link expireRoots}.
   */
  isValidRoot(root: BigNumberish): boolean {
    const value = BigInt(root);
    if (value === 0n) return false;
    if (value === this.tree.root) return true;
    return this.history.isWithinGrace(value, this.clock());
  }

  /** A membership proof, for in-process holders. Remote holders rebuild from {@link leaves}. */
  generateProof(commitment: BigNumberish): IssuerProof {
    return this.tree.generateProof(toCommitment(commitment, sha256Scheme));
  }

  toJSON(): IssuerAuthorityState {
    return {
      version: 1,
      maxDepth: this.maxDepth,
      tree: this.tree.export(),
      history: this.history.toJSON(),
    };
  }

  /**
   * @param validate Rehash the tree from its leaves. Pass `false` only for state this process produced.
   */
  static fromJSON(
    state: IssuerAuthorityState,
    options: { clock?: Clock; validate?: boolean } = {},
  ): IssuerRegistryAuthority {
    if (state.version !== 1) {
      throw new RegistryError("INVALID_INPUT", `Unsupported issuer registry state version ${String(state.version)}`);
    }
    const authority = new IssuerRegistryAuthority({
      maxDepth: state.maxDepth,
      rootDuration: state.history.rootDuration,
      clock: options.clock,
    });
    authority.tree = IssuerRegistry.import(state.tree, options.validate ?? true, sha256Scheme);
    authority.history = RootHistory.fromJSON(state.history);
    return authority;
  }

  private write(operation: (tree: IssuerRegistry) => void): bigint {
    const oldRoot = this.tree.root;
    const snapshot = this.tree.export();
    try {
      operation(this.tree);
      if (this.tree.depth > this.maxDepth) {
        throw new RegistryError(
          "MAX_DEPTH_EXCEEDED",
          `Issuer tree depth ${this.tree.depth} would exceed the circuit's max depth ${this.maxDepth}`,
        );
      }
    } catch (error) {
      this.tree = IssuerRegistry.import(snapshot, false, sha256Scheme);
      throw toRegistryError(error);
    }
    const newRoot = this.tree.root;
    // The empty root is never accepted, so it gets no grace period.
    this.history.replace(oldRoot === 0n ? undefined : oldRoot, newRoot, this.clock());
    return newRoot;
  }
}

export function checkMaxDepth(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RegistryError("INVALID_INPUT", "maxDepth must be a positive integer");
  }
  return value;
}

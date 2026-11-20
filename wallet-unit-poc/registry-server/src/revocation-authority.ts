import {
  RevocationRegistry,
  sha256Scheme,
  toCommitment,
  type BigNumberish,
  type RevocationLeaf,
  type RevocationProof,
} from "@coordination-network/revocation-registry";

import { RegistryError, toRegistryError } from "./errors.js";
import { DEFAULT_ROOT_DURATION, RootHistory, systemClock, type Clock, type RootHistoryState } from "./root-history.js";

export interface RevocationAuthorityOptions {
  /** Seconds a superseded root stays valid. */
  rootDuration?: number;
  clock?: Clock;
}

export interface RevocationAuthorityState {
  version: 1;
  /** `RevocationRegistry.export()` output. */
  tree: string;
  history: RootHistoryState;
}

/**
 * OpenAC's revocation registry, held off chain and shared by every issuer: a
 * SHA-256 LeanIMT+ of revoked `sha256(r)` commitments. Behaves like
 * `OpenACRevocationRegistry` over `Sha256Revocation`: the same tree, roots and
 * root history. Only the owner writes, on behalf of every issuer.
 *
 * Every write is all or nothing: on any failure the tree is restored.
 */
export class RevocationRegistryAuthority {
  private tree: RevocationRegistry;
  private history: RootHistory;
  private readonly clock: Clock;

  constructor(options: RevocationAuthorityOptions = {}) {
    this.tree = new RevocationRegistry([], sha256Scheme);
    this.history = new RootHistory(options.rootDuration ?? DEFAULT_ROOT_DURATION);
    this.clock = options.clock ?? systemClock;
  }

  /** `0` while empty. Unlike the issuer registry, the empty root is a valid root. */
  get root(): bigint {
    return this.tree.root;
  }

  get depth(): number {
    return this.tree.depth;
  }

  /** The number of revoked commitments. */
  get size(): number {
    return this.tree.size;
  }

  /**
   * Every physical slot in index order, sentinel and tombstones included. What
   * holders rebuild from with `RevocationRegistry.fromLeaves`, like `getLeaf` on chain.
   */
  get leafSlots(): RevocationLeaf[] {
    return this.tree.leafSlots;
  }

  get rootDuration(): number {
    return this.history.rootDuration;
  }

  isRevoked(commitment: BigNumberish): boolean {
    return this.tree.isRevoked(commitment);
  }

  revoke(commitment: BigNumberish): bigint {
    return this.revokeMany([commitment]);
  }

  revokeMany(commitments: BigNumberish[]): bigint {
    if (commitments.length === 0) throw new RegistryError("INVALID_INPUT", "No revocation commitments");
    const values = commitments.map((c) => parseCommitment(c));
    return this.write((tree) => tree.revokeMany(values));
  }

  /**
   * Tombstones a commitment. The credential verifies again for anyone still
   * accepting an older root, so revocation is normally permanent.
   */
  unrevoke(commitment: BigNumberish): bigint {
    const value = parseCommitment(commitment);
    return this.write((tree) => tree.unrevoke(value));
  }

  updateRevocationCommitment(oldCommitment: BigNumberish, newCommitment: BigNumberish): bigint {
    const oldValue = parseCommitment(oldCommitment);
    const newValue = parseCommitment(newCommitment);
    return this.write((tree) => tree.updateCommitment(oldValue, newValue));
  }

  updateRootDuration(rootDuration: number): void {
    this.history.rootDuration = rootDuration;
  }

  /**
   * Whether a presentation's revocation root is accepted: the current root
   * (including `0` while empty), or one superseded less than `rootDuration`
   * seconds ago.
   */
  isValidRoot(root: BigNumberish): boolean {
    const value = BigInt(root);
    if (value === this.tree.root) return true;
    return this.history.isWithinGrace(value, this.clock());
  }

  /** Non-membership (`proofType: 1`) or membership (`proofType: 0`) proof, for in-process holders. */
  generateProof(commitment: BigNumberish): RevocationProof {
    return this.tree.generateProof(parseCommitment(commitment));
  }

  toJSON(): RevocationAuthorityState {
    return {
      version: 1,
      tree: this.tree.export(),
      history: this.history.toJSON(),
    };
  }

  /**
   * @param validate Rehash the tree from its leaves. Pass `false` only for state this process produced.
   */
  static fromJSON(
    state: RevocationAuthorityState,
    options: { clock?: Clock; validate?: boolean } = {},
  ): RevocationRegistryAuthority {
    if (state.version !== 1) {
      throw new RegistryError("INVALID_INPUT", `Unsupported revocation registry state version ${String(state.version)}`);
    }
    const authority = new RevocationRegistryAuthority({ clock: options.clock });
    authority.tree = RevocationRegistry.import(state.tree, options.validate ?? true, sha256Scheme);
    authority.history = RootHistory.fromJSON(state.history);
    return authority;
  }

  private write(operation: (tree: RevocationRegistry) => void): bigint {
    const oldRoot = this.tree.root;
    const snapshot = this.tree.export();
    try {
      operation(this.tree);
    } catch (error) {
      // `RevocationRegistry.revokeMany` keeps the commitments before a rejected one, so restore.
      this.tree = RevocationRegistry.import(snapshot, false, sha256Scheme);
      throw toRegistryError(error);
    }
    const newRoot = this.tree.root;
    this.history.replace(oldRoot, newRoot, this.clock());
    return newRoot;
  }
}

function parseCommitment(value: BigNumberish): bigint {
  try {
    return toCommitment(value, sha256Scheme);
  } catch (error) {
    throw toRegistryError(error);
  }
}

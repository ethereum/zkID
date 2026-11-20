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
  /** `[revokerId, authorized]` pairs. */
  revokers: [string, boolean][];
  /** `[commitment, revokerId]` pairs, commitment as a decimal string. */
  revokedBy: [string, string][];
}

/**
 * OpenAC's revocation registry, held off chain and shared by every issuer: a
 * SHA-256 LeanIMT+ of revoked `sha256(r)` commitments. Behaves like
 * `OpenACRevocationRegistry` over `Sha256Revocation`: the same tree and roots,
 * the same root history, authorized revokers (one per issuer), and
 * `revokedBy`, so only the revoker that revoked a commitment can unrevoke or
 * update it.
 *
 * Revokers are named by an opaque id instead of an address. Every write is all
 * or nothing: on any failure the tree is restored.
 */
export class RevocationRegistryAuthority {
  private tree: RevocationRegistry;
  private history: RootHistory;
  private readonly revokers = new Map<string, boolean>();
  private readonly commitmentRevokers = new Map<bigint, string>();
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

  /** The revoker that revoked a commitment, or `undefined` if it is not revoked. */
  revokedBy(commitment: BigNumberish): string | undefined {
    return this.commitmentRevokers.get(BigInt(commitment));
  }

  isRevoker(revokerId: string): boolean {
    return this.revokers.get(revokerId) === true;
  }

  /** Ids of every revoker ever configured, with whether each is authorized now. */
  get revokerIds(): [string, boolean][] {
    return [...this.revokers];
  }

  /**
   * Authorizes or deauthorizes a revoker. A deauthorized revoker keeps its
   * revocations but can no longer revoke, unrevoke or update.
   */
  setRevoker(revokerId: string, authorized: boolean): void {
    checkRevokerId(revokerId);
    this.revokers.set(revokerId, authorized);
  }

  revoke(revokerId: string, commitment: BigNumberish): bigint {
    return this.revokeMany(revokerId, [commitment]);
  }

  revokeMany(revokerId: string, commitments: BigNumberish[]): bigint {
    this.requireRevoker(revokerId);
    if (commitments.length === 0) throw new RegistryError("INVALID_INPUT", "No revocation commitments");
    const values = commitments.map((c) => parseCommitment(c));
    const root = this.write((tree) => tree.revokeMany(values));
    for (const value of values) this.commitmentRevokers.set(value, revokerId);
    return root;
  }

  /**
   * Tombstones a commitment. The credential verifies again for anyone still
   * accepting an older root, so revocation is normally permanent.
   */
  unrevoke(revokerId: string, commitment: BigNumberish): bigint {
    const value = parseCommitment(commitment);
    this.requireCommitmentRevoker(revokerId, value);
    const root = this.write((tree) => tree.unrevoke(value));
    this.commitmentRevokers.delete(value);
    return root;
  }

  updateRevocationCommitment(
    revokerId: string,
    oldCommitment: BigNumberish,
    newCommitment: BigNumberish,
  ): bigint {
    const oldValue = parseCommitment(oldCommitment);
    const newValue = parseCommitment(newCommitment);
    this.requireCommitmentRevoker(revokerId, oldValue);
    const root = this.write((tree) => tree.updateCommitment(oldValue, newValue));
    this.commitmentRevokers.delete(oldValue);
    this.commitmentRevokers.set(newValue, revokerId);
    return root;
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
      revokers: [...this.revokers],
      revokedBy: [...this.commitmentRevokers].map(([c, id]) => [c.toString(), id]),
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
    for (const [id, authorized] of state.revokers) authority.setRevoker(id, authorized);
    for (const [c, id] of state.revokedBy) {
      const value = BigInt(c);
      if (!authority.tree.isRevoked(value)) {
        throw new RegistryError("INVALID_INPUT", `revokedBy lists ${c}, which is not revoked`);
      }
      authority.commitmentRevokers.set(value, id);
    }
    return authority;
  }

  private requireRevoker(revokerId: string): void {
    if (!this.isRevoker(revokerId)) {
      throw new RegistryError("FORBIDDEN", `${revokerId} is not an authorized revoker`);
    }
  }

  private requireCommitmentRevoker(revokerId: string, commitment: bigint): void {
    this.requireRevoker(revokerId);
    if (this.commitmentRevokers.get(commitment) !== revokerId) {
      throw new RegistryError("FORBIDDEN", `${revokerId} did not revoke ${commitment}`);
    }
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

function checkRevokerId(revokerId: unknown): void {
  if (typeof revokerId !== "string" || !/^[A-Za-z0-9._-]{1,64}$/.test(revokerId)) {
    throw new RegistryError("INVALID_INPUT", "A revoker id must be 1 to 64 characters of [A-Za-z0-9._-]");
  }
}

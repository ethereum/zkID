import { RegistryError } from "./errors.js";

/** Current time in Unix seconds, the unit of `rootDuration`. */
export type Clock = () => number;

export const systemClock: Clock = () => Math.floor(Date.now() / 1000);

/** Same default as the coordination-network services and the OpenAC ignition modules. */
export const DEFAULT_ROOT_DURATION = 3600;

export interface RootHistoryState {
  rootDuration: number;
  /** `[root, supersededAt]` pairs, root as a decimal string. */
  superseded: [string, number][];
  /** When {@link RootHistory.expireAll} last ran, if ever. */
  rootsExpiredAt?: number;
  /** The root that was current at that expiry, as a decimal string. */
  rootAtExpiry?: string;
}

/**
 * When each past root stopped being current, so a proof built against a recent
 * root still verifies for `rootDuration` seconds after a write. Same rules as
 * `rootSupersededAt` in the on-chain services: the check is strict, so a
 * duration of 0 gives no grace, and a root that becomes current again loses its
 * stamp. Stamps are kept forever, as on chain, so raising `rootDuration` can
 * make a recently superseded root valid again on both.
 */
export class RootHistory {
  private readonly superseded = new Map<bigint, number>();
  private duration: number;
  private rootsExpiredAt: number | undefined;
  private rootAtExpiry: bigint | undefined;

  constructor(rootDuration: number = DEFAULT_ROOT_DURATION) {
    this.duration = checkRootDuration(rootDuration);
  }

  get rootDuration(): number {
    return this.duration;
  }

  set rootDuration(value: number) {
    this.duration = checkRootDuration(value);
  }

  /**
   * Records a write that moved the current root from `oldRoot` to `newRoot`.
   * Pass `oldRoot` as `undefined` to skip stamping it (the issuer registry never
   * accepts the empty root).
   */
  replace(oldRoot: bigint | undefined, newRoot: bigint, now: number): void {
    if (oldRoot !== undefined) this.superseded.set(oldRoot, now);
    this.superseded.delete(newRoot);
  }

  /**
   * Rejects every root superseded so far, as `expireRegistryRoots` on chain:
   * records the time and the current root instead of dropping stamps, so a
   * root superseded in the same second as the expiry is only accepted if it
   * was the one current at the expiry.
   */
  expireAll(currentRoot: bigint, now: number): void {
    this.rootsExpiredAt = now;
    this.rootAtExpiry = currentRoot;
  }

  supersededAt(root: bigint): number | undefined {
    return this.superseded.get(root);
  }

  /** Whether a superseded root is still inside its grace period. Says nothing about the current root. */
  isWithinGrace(root: bigint, now: number): boolean {
    const supersededAt = this.superseded.get(root);
    if (supersededAt === undefined) return false;
    if (this.rootsExpiredAt !== undefined) {
      if (supersededAt < this.rootsExpiredAt) return false;
      if (supersededAt === this.rootsExpiredAt && root !== this.rootAtExpiry) return false;
    }
    return now - supersededAt < this.duration;
  }

  toJSON(): RootHistoryState {
    return {
      rootDuration: this.duration,
      superseded: [...this.superseded].map(([root, at]) => [root.toString(), at]),
      ...(this.rootsExpiredAt === undefined
        ? {}
        : { rootsExpiredAt: this.rootsExpiredAt, rootAtExpiry: (this.rootAtExpiry ?? 0n).toString() }),
    };
  }

  static fromJSON(state: RootHistoryState): RootHistory {
    const history = new RootHistory(state.rootDuration);
    for (const [root, at] of state.superseded) {
      if (!Number.isSafeInteger(at) || at < 0) {
        throw new RegistryError("INVALID_INPUT", `Invalid superseded timestamp for root ${root}`);
      }
      history.superseded.set(BigInt(root), at);
    }
    if (state.rootsExpiredAt !== undefined) {
      if (!Number.isSafeInteger(state.rootsExpiredAt) || state.rootsExpiredAt < 0 || state.rootAtExpiry === undefined) {
        throw new RegistryError("INVALID_INPUT", "Invalid root expiry");
      }
      history.rootsExpiredAt = state.rootsExpiredAt;
      history.rootAtExpiry = BigInt(state.rootAtExpiry);
    }
    return history;
  }
}

export function checkRootDuration(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new RegistryError("INVALID_INPUT", "rootDuration must be a non-negative integer number of seconds");
  }
  return value;
}

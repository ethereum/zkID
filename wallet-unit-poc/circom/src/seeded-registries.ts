import { sha256 } from "@noble/hashes/sha2";
import { IssuerRegistry, sha256Scheme as issuerScheme } from "@coordination-network/issuer-registry";
import { RevocationRegistry, sha256Scheme as revocationScheme } from "@coordination-network/revocation-registry";
import { bytesToBigInt } from "./revocation.ts";
import { issuerCommitment, type IssuerKeyPoint } from "./issuer-hiding.ts";

/** `count` 256-bit values, `sha256("<label>|<seed>|<i>")`, so one seed always gives one registry. */
export function seededCommitments(label: string, seed: number, count: number): bigint[] {
  const enc = new TextEncoder();
  return Array.from({ length: count }, (_, i) => bytesToBigInt(sha256(enc.encode(`${label}|${seed}|${i}`))));
}

/** A revocation registry of `revoked` seeded commitments. */
export function buildSeededRevocationRegistry(revoked: number, seed: number): RevocationRegistry {
  return new RevocationRegistry(seededCommitments("rev", seed, revoked), revocationScheme);
}

/** An issuer registry of `issuers` leaves: `issuers - 1` seeded ones, then `issuer` last. */
export function buildSeededIssuerRegistry(issuer: IssuerKeyPoint, issuers: number, seed: number): IssuerRegistry {
  const leaves = [...seededCommitments("iss", seed, issuers - 1), issuerCommitment(issuer)];
  return new IssuerRegistry(leaves, issuerScheme);
}

/** Seeded-registry mode: set when any of --issuers, --revoked or --seed is passed; --out alone does not start it. */
export interface RegistryOptions {
  issuers: number;
  revoked: number;
  seed: number;
}

export function parseSeededFlags(args: string[]): RegistryOptions | undefined {
  const flag = (name: string): string | undefined => {
    const i = args.indexOf(name);
    return i === -1 ? undefined : args[i + 1];
  };
  if (!["--issuers", "--revoked", "--seed"].some((f) => args.includes(f))) return undefined;
  return {
    issuers: Number(flag("--issuers") ?? 256),
    revoked: Number(flag("--revoked") ?? 5),
    seed: Number(flag("--seed") ?? 1),
  };
}

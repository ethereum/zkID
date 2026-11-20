#!/usr/bin/env node
import { join } from "node:path";

import { DEFAULT_ISSUER_MAX_DEPTH } from "./issuer-authority.js";
import { DEFAULT_ROOT_DURATION } from "./root-history.js";
import { createRegistryServer } from "./server.js";
import { FileStore } from "./store.js";

// A registry is served only when its owner token is set.
const env = process.env;
const dataDir = env.DATA_DIR ?? "./data";
const issuerOwnerToken = env.ISSUER_OWNER_TOKEN;
const revocationOwnerToken = env.REVOCATION_OWNER_TOKEN;

if (!issuerOwnerToken && !revocationOwnerToken) {
  console.error("Set ISSUER_OWNER_TOKEN and/or REVOCATION_OWNER_TOKEN to serve the matching registry.");
  process.exit(1);
}

const rootDuration = integer("ROOT_DURATION", DEFAULT_ROOT_DURATION);

const registry = await createRegistryServer({
  issuer: issuerOwnerToken
    ? {
        ownerToken: issuerOwnerToken,
        store: new FileStore(join(dataDir, "issuer-registry.json")),
        maxDepth: maxDepth("ISSUER_MAX_DEPTH", DEFAULT_ISSUER_MAX_DEPTH),
        rootDuration,
      }
    : undefined,
  revocation: revocationOwnerToken
    ? {
        ownerToken: revocationOwnerToken,
        store: new FileStore(join(dataDir, "revocation-registry.json")),
        rootDuration,
      }
    : undefined,
  corsOrigin: env.CORS_ORIGIN === "" ? null : (env.CORS_ORIGIN ?? "*"),
});

const url = await registry.listen(integer("PORT", 8787), env.HOST ?? "127.0.0.1");
console.log(`OpenAC registry server on ${url}`);
if (registry.issuer) console.log(`  issuer registry      root ${registry.issuer.root}`);
if (registry.revocation) console.log(`  revocation registry  root ${registry.revocation.root}`);

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, () => {
    void registry.close().then(() => process.exit(0));
  });
}

/**
 * A tree deeper than the compiled Show circuit's limit cannot be proven
 * against, so the limit is the ceiling as well as the default.
 */
function maxDepth(name: string, circuitLimit: number): number {
  const value = integer(name, circuitLimit);
  if (value < 1 || value > circuitLimit) {
    console.error(`${name} must be between 1 and ${circuitLimit}, the Show circuit's max depth`);
    process.exit(1);
  }
  return value;
}

function integer(name: string, fallback: number): number {
  const raw = env[name];
  if (raw === undefined || raw === "") return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 0) {
    console.error(`${name} must be a non-negative integer`);
    process.exit(1);
  }
  return value;
}

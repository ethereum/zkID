import { Hono, type Context } from "hono";
import { bodyLimit } from "hono/body-limit";
import { cors } from "hono/cors";
import type { ContentfulStatusCode } from "hono/utils/http-status";

import { bearerToken, hashToken, tokenMatches } from "./auth.js";
import { RegistryError, type RegistryErrorCode } from "./errors.js";
import { IssuerRegistryAuthority, type IssuerAuthorityState } from "./issuer-authority.js";
import { RevocationRegistryAuthority, type RevocationAuthorityState } from "./revocation-authority.js";
import { checkRootDuration, systemClock, type Clock } from "./root-history.js";
import { MemoryStore, type StateStore } from "./store.js";

export interface IssuerServiceOptions {
  /** Bearer token for every issuer registry write. */
  ownerToken: string;
  store?: StateStore<IssuerAuthorityState>;
  /** Used only when the store is empty. */
  maxDepth?: number;
  /** Used only when the store is empty. */
  rootDuration?: number;
}

export interface RevocationServiceOptions {
  /** Bearer token for every revocation registry write. */
  ownerToken: string;
  store?: StateStore<RevocationAuthorityState>;
  /** Used only when the store is empty. */
  rootDuration?: number;
}

export interface RegistryAppOptions {
  /** Serve the issuer registry under `/issuer`. */
  issuer?: IssuerServiceOptions;
  /** Serve the revocation registry under `/revocation`. */
  revocation?: RevocationServiceOptions;
  clock?: Clock;
  /** `Access-Control-Allow-Origin`, so browser wallets and verifiers can read. Default `*`; `null` disables CORS. */
  corsOrigin?: string | null;
  /** Largest accepted request body in bytes. Default 1 MiB. */
  bodyLimit?: number;
}

export interface RegistryApp {
  /** The Hono app. Serve it with any Hono adapter, or mount it with `app.route()`. */
  readonly app: Hono;
  /** The live issuer registry, read only. Writes go through the HTTP API so they are persisted. */
  readonly issuer: IssuerRegistryAuthority | undefined;
  /** The live revocation registry, read only. */
  readonly revocation: RevocationRegistryAuthority | undefined;
}

/**
 * State that is only replaced once saved: a write runs on a copy, the copy is
 * persisted, then it becomes current. Readers never see an unsaved root, and
 * writes run one at a time.
 */
class Persisted<T, S> {
  private tail: Promise<void> = Promise.resolve();

  constructor(
    private value: T,
    private readonly encode: (value: T) => S,
    private readonly copy: (state: S) => T,
    private readonly store: StateStore<S>,
  ) {}

  get current(): T {
    return this.value;
  }

  write<R>(operation: (draft: T) => R): Promise<R> {
    const run = this.tail.then(async () => {
      const draft = this.copy(this.encode(this.value));
      const result = operation(draft);
      try {
        await this.store.save(this.encode(draft));
      } catch (error) {
        throw new RegistryError(
          "STORAGE_FAILED",
          `Could not persist the registry: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
      this.value = draft;
      return result;
    });
    this.tail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }
}

const UINT256_LIMIT = 1n << 256n;

const STATUS: Record<RegistryErrorCode, ContentfulStatusCode> = {
  INVALID_INPUT: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  METHOD_NOT_ALLOWED: 405,
  MAX_DEPTH_EXCEEDED: 409,
  PAYLOAD_TOO_LARGE: 413,
  STORAGE_FAILED: 503,
};

/**
 * Creates the registry Hono app and loads each registry from its store (in
 * memory when none is given). Values are uint256s, sent and returned as
 * decimal strings; requests may also use 0x-prefixed hex.
 */
export async function createRegistryApp(options: RegistryAppOptions): Promise<RegistryApp> {
  if (!options.issuer && !options.revocation) {
    throw new RegistryError("INVALID_INPUT", "Enable at least one of the issuer and revocation registries");
  }
  const clock = options.clock ?? systemClock;
  const corsOrigin = options.corsOrigin === undefined ? "*" : options.corsOrigin;
  const maxBodySize = options.bodyLimit ?? 1024 * 1024;

  const app = new Hono();

  if (corsOrigin !== null) {
    app.use(
      "*",
      cors({
        origin: corsOrigin,
        allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allowHeaders: ["Authorization", "Content-Type"],
      }),
    );
  }
  app.use(
    "*",
    bodyLimit({
      maxSize: maxBodySize,
      onError: () => {
        throw new RegistryError("PAYLOAD_TOO_LARGE", `Request body exceeds ${maxBodySize} bytes`);
      },
    }),
  );

  app.onError((error, c) => {
    if (error instanceof RegistryError) {
      return json(c, { error: error.code, message: error.message }, STATUS[error.code]);
    }
    return json(c, { error: "INTERNAL", message: "Internal server error" }, 500);
  });
  app.notFound((c) => json(c, { error: "NOT_FOUND", message: `No route for ${c.req.path}` }, 404));

  let issuer: Persisted<IssuerRegistryAuthority, IssuerAuthorityState> | undefined;
  if (options.issuer) {
    const config = options.issuer;
    const store = config.store ?? new MemoryStore<IssuerAuthorityState>();
    const saved = await store.load();
    const initial = saved
      ? IssuerRegistryAuthority.fromJSON(saved, { clock })
      : new IssuerRegistryAuthority({ maxDepth: config.maxDepth, rootDuration: config.rootDuration, clock });
    issuer = new Persisted(
      initial,
      (a) => a.toJSON(),
      (s) => IssuerRegistryAuthority.fromJSON(s, { clock, validate: false }),
      store,
    );
    app.route("/issuer", issuerRoutes(issuer, ownerTokenHash(config.ownerToken, "issuer")));
  }

  let revocation: Persisted<RevocationRegistryAuthority, RevocationAuthorityState> | undefined;
  if (options.revocation) {
    const config = options.revocation;
    const store = config.store ?? new MemoryStore<RevocationAuthorityState>();
    const saved = await store.load();
    const initial = saved
      ? RevocationRegistryAuthority.fromJSON(saved, { clock })
      : new RevocationRegistryAuthority({ rootDuration: config.rootDuration, clock });
    revocation = new Persisted(
      initial,
      (a) => a.toJSON(),
      (s) => RevocationRegistryAuthority.fromJSON(s, { clock, validate: false }),
      store,
    );
    app.route("/revocation", revocationRoutes(revocation, ownerTokenHash(config.ownerToken, "revocation")));
  }

  app.get("/health", (c) => json(c, { ok: true, issuer: issuer !== undefined, revocation: revocation !== undefined }));

  return {
    app,
    get issuer() {
      return issuer?.current;
    },
    get revocation() {
      return revocation?.current;
    },
  };
}

function issuerRoutes(registry: Persisted<IssuerRegistryAuthority, IssuerAuthorityState>, ownerHash: string): Hono {
  const routes = new Hono();
  const owner = (c: Context) => requireOwner(bearerToken(c.req.header("Authorization")), ownerHash);

  routes.get("/", (c) => {
    const r = registry.current;
    return json(c, {
      root: r.root,
      depth: r.depth,
      size: r.size,
      maxDepth: r.maxDepth,
      rootDuration: r.rootDuration,
      leaves: r.leaves,
    });
  });

  routes.get("/root", (c) => json(c, { root: registry.current.root }));

  routes.get("/roots/:root", (c) => {
    const root = parseUint256(c.req.param("root"), "root");
    return json(c, { root, valid: registry.current.isValidRoot(root) });
  });

  routes.get("/commitments/:commitment", (c) => {
    const commitment = parseUint256(c.req.param("commitment"), "commitment");
    const index = commitment === 0n ? -1 : registry.current.indexOf(commitment);
    return json(c, { commitment, isIssuer: index >= 0, index });
  });

  routes.post("/commitments", async (c) => {
    owner(c);
    const commitments = parseUint256List((await readBody(c)).commitments, "commitments");
    return json(c, { root: await registry.write((r) => r.addIssuers(commitments)) });
  });

  routes.put("/commitments/:commitment", async (c) => {
    owner(c);
    const oldCommitment = parseUint256(c.req.param("commitment"), "commitment");
    const newCommitment = parseUint256((await readBody(c)).newCommitment, "newCommitment");
    return json(c, { root: await registry.write((r) => r.updateIssuerCommitment(oldCommitment, newCommitment)) });
  });

  routes.delete("/commitments/:commitment", async (c) => {
    owner(c);
    const commitment = parseUint256(c.req.param("commitment"), "commitment");
    return json(c, { root: await registry.write((r) => r.removeIssuer(commitment)) });
  });

  routes.put("/root-duration", async (c) => {
    owner(c);
    const rootDuration = checkRootDuration((await readBody(c)).rootDuration);
    await registry.write((r) => r.updateRootDuration(rootDuration));
    return json(c, { rootDuration });
  });

  routes.post("/expire-roots", async (c) => {
    owner(c);
    await registry.write((r) => r.expireRoots());
    return json(c, { root: registry.current.root });
  });

  return withMethodNotAllowed(routes);
}

function revocationRoutes(
  registry: Persisted<RevocationRegistryAuthority, RevocationAuthorityState>,
  ownerHash: string,
): Hono {
  const routes = new Hono();
  const owner = (c: Context) => requireOwner(bearerToken(c.req.header("Authorization")), ownerHash);

  routes.get("/", (c) => {
    const r = registry.current;
    return json(c, {
      root: r.root,
      depth: r.depth,
      size: r.size,
      rootDuration: r.rootDuration,
      leaves: r.leafSlots.map(({ value, nextValue }) => ({ value, nextValue })),
    });
  });

  routes.get("/root", (c) => json(c, { root: registry.current.root }));

  routes.get("/roots/:root", (c) => {
    const root = parseUint256(c.req.param("root"), "root");
    return json(c, { root, valid: registry.current.isValidRoot(root) });
  });

  routes.get("/commitments/:commitment", (c) => {
    const commitment = parseUint256(c.req.param("commitment"), "commitment");
    return json(c, { commitment, isRevoked: commitment !== 0n && registry.current.isRevoked(commitment) });
  });

  routes.post("/commitments", async (c) => {
    owner(c);
    const commitments = parseUint256List((await readBody(c)).commitments, "commitments");
    return json(c, { root: await registry.write((r) => r.revokeMany(commitments)) });
  });

  routes.put("/commitments/:commitment", async (c) => {
    owner(c);
    const oldCommitment = parseUint256(c.req.param("commitment"), "commitment");
    const newCommitment = parseUint256((await readBody(c)).newCommitment, "newCommitment");
    return json(c, { root: await registry.write((r) => r.updateRevocationCommitment(oldCommitment, newCommitment)) });
  });

  routes.delete("/commitments/:commitment", async (c) => {
    owner(c);
    const commitment = parseUint256(c.req.param("commitment"), "commitment");
    return json(c, { root: await registry.write((r) => r.unrevoke(commitment)) });
  });

  routes.put("/root-duration", async (c) => {
    owner(c);
    const rootDuration = checkRootDuration((await readBody(c)).rootDuration);
    await registry.write((r) => r.updateRootDuration(rootDuration));
    return json(c, { rootDuration });
  });

  return withMethodNotAllowed(routes);
}

/**
 * Answers 405 for a known path with an unhandled method. Registered last, so
 * it only runs when no method-specific handler matched.
 */
function withMethodNotAllowed(routes: Hono): Hono {
  const paths = new Set(routes.routes.map((route) => route.path));
  for (const path of paths) {
    routes.all(path, (c) => {
      throw new RegistryError("METHOD_NOT_ALLOWED", `${c.req.method} is not allowed on ${c.req.path}`);
    });
  }
  return routes;
}

/** JSON with bigints as decimal strings. Registry state changes on every write, so nothing is cached. */
function json(c: Context, value: unknown, status: ContentfulStatusCode = 200): Response {
  const text = JSON.stringify(value, (_key, v) => (typeof v === "bigint" ? v.toString() : v));
  return c.body(text, status, { "Content-Type": "application/json", "Cache-Control": "no-store" });
}

async function readBody(c: Context): Promise<Record<string, unknown>> {
  const text = await c.req.text();
  if (text.length === 0) return {};
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new RegistryError("INVALID_INPUT", "Request body is not valid JSON");
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw new RegistryError("INVALID_INPUT", "Request body must be a JSON object");
  }
  return body as Record<string, unknown>;
}

function requireOwner(token: string | undefined, ownerHash: string): void {
  if (token === undefined) throw new RegistryError("UNAUTHORIZED", "Missing bearer token");
  if (!tokenMatches(token, ownerHash)) throw new RegistryError("FORBIDDEN", "Not the registry owner");
}

function ownerTokenHash(token: string, registry: string): string {
  if (typeof token !== "string" || token.length < 16) {
    throw new RegistryError("INVALID_INPUT", `The ${registry} owner token must be at least 16 characters`);
  }
  return hashToken(token);
}

export function parseUint256(value: unknown, field: string): bigint {
  if (typeof value !== "string" || !/^(0x[0-9a-fA-F]{1,64}|[0-9]{1,78})$/.test(value)) {
    throw new RegistryError("INVALID_INPUT", `${field} must be a uint256 as a decimal or 0x-hex string`);
  }
  const parsed = BigInt(value);
  if (parsed >= UINT256_LIMIT) throw new RegistryError("INVALID_INPUT", `${field} must be below 2^256`);
  return parsed;
}

function parseUint256List(value: unknown, field: string): bigint[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new RegistryError("INVALID_INPUT", `${field} must be a non-empty array`);
  }
  return value.map((item, i) => parseUint256(item, `${field}[${i}]`));
}

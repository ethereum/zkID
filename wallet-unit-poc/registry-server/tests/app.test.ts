import { describe, expect, it } from "vitest";

import { createRegistryApp } from "../src/index.js";

const OWNER = "issuer-owner-token-0123456789";

describe("registry app", () => {
  it("answers requests in process, without a listening server", async () => {
    const { app } = await createRegistryApp({ issuer: { ownerToken: OWNER } });

    const write = await app.request("/issuer/commitments", {
      method: "POST",
      headers: { Authorization: `Bearer ${OWNER}`, "Content-Type": "application/json" },
      body: JSON.stringify({ commitments: ["0x1234", "99"] }),
    });
    expect(write.status).toBe(200);
    const { root } = (await write.json()) as { root: string };

    const read = await app.request("/issuer");
    expect(read.headers.get("Cache-Control")).toBe("no-store");
    expect(await read.json()).toMatchObject({ root, size: 2, leaves: ["4660", "99"] });
  });

  it("serves only the registries it was given", async () => {
    const { app } = await createRegistryApp({ issuer: { ownerToken: OWNER } });
    expect((await app.request("/revocation/root")).status).toBe(404);
    expect(await (await app.request("/health")).json()).toEqual({ ok: true, issuer: true, revocation: false });
  });

  it("answers CORS preflights, unless disabled", async () => {
    const preflight = {
      method: "OPTIONS",
      headers: {
        Origin: "https://wallet.example",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization,content-type",
      },
    };

    const open = await createRegistryApp({ issuer: { ownerToken: OWNER } });
    const allowed = await open.app.request("/issuer/commitments", preflight);
    expect(allowed.status).toBe(204);
    expect(allowed.headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect(allowed.headers.get("Access-Control-Allow-Headers")).toMatch(/Authorization/);

    const closed = await createRegistryApp({ issuer: { ownerToken: OWNER }, corsOrigin: null });
    const read = await closed.app.request("/issuer/root", { headers: { Origin: "https://wallet.example" } });
    expect(read.headers.get("Access-Control-Allow-Origin")).toBeNull();
  });

  it("rejects bodies over the limit", async () => {
    const { app } = await createRegistryApp({ issuer: { ownerToken: OWNER }, bodyLimit: 64 });
    const response = await app.request("/issuer/commitments", {
      method: "POST",
      headers: { Authorization: `Bearer ${OWNER}`, "Content-Type": "application/json" },
      body: JSON.stringify({ commitments: Array.from({ length: 20 }, (_, i) => String(i + 1)) }),
    });
    expect(response.status).toBe(413);
    expect(await response.json()).toMatchObject({ error: "PAYLOAD_TOO_LARGE" });
  });

  it("refuses a weak owner token", async () => {
    await expect(createRegistryApp({ issuer: { ownerToken: "short" } })).rejects.toMatchObject({
      code: "INVALID_INPUT",
    });
  });
});

describe("revocation writes", () => {
  const REVOCATION_OWNER = "revocation-owner-token-0123456789";

  function post(app: { request: (path: string, init: RequestInit) => Response | Promise<Response> }, token: string | undefined, body: string) {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (token) headers.Authorization = `Bearer ${token}`;
    return app.request("/revocation/commitments", { method: "POST", headers, body });
  }

  it("checks the owner token before reading the body", async () => {
    const { app } = await createRegistryApp({ revocation: { ownerToken: REVOCATION_OWNER } });
    expect((await post(app, undefined, "not json")).status).toBe(401);
    expect((await post(app, "unknown-token", "not json")).status).toBe(403);
  });

  it("revokes with the owner token", async () => {
    const registry = await createRegistryApp({ revocation: { ownerToken: REVOCATION_OWNER } });
    expect((await post(registry.app, REVOCATION_OWNER, JSON.stringify({ commitments: ["5"] }))).status).toBe(200);
    expect(registry.revocation!.isRevoked(5n)).toBe(true);
  });
});

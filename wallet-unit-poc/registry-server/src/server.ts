import type { Server } from "node:http";
import type { AddressInfo } from "node:net";

import { createAdaptorServer } from "@hono/node-server";

import { createRegistryApp, type RegistryApp, type RegistryAppOptions } from "./app.js";

export type RegistryServerOptions = RegistryAppOptions;

export interface RegistryServer extends RegistryApp {
  readonly server: Server;
  /** Starts listening and resolves to the base URL. Port 0 picks a free port. */
  listen(port?: number, host?: string): Promise<string>;
  close(): Promise<void>;
}

/** The registry app on a Node HTTP server, not yet listening. */
export async function createRegistryServer(options: RegistryServerOptions): Promise<RegistryServer> {
  const registry = await createRegistryApp(options);
  const server = createAdaptorServer({ fetch: registry.app.fetch }) as Server;

  return {
    app: registry.app,
    server,
    get issuer() {
      return registry.issuer;
    },
    get revocation() {
      return registry.revocation;
    },
    listen(port = 0, host = "127.0.0.1") {
      return new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, host, () => {
          server.off("error", reject);
          const address = server.address() as AddressInfo;
          const shownHost = address.family === "IPv6" ? `[${address.address}]` : address.address;
          resolve(`http://${shownHost}:${address.port}`);
        });
      });
    },
    close() {
      return new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
        server.closeAllConnections();
      });
    },
  };
}

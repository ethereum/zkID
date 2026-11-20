# OpenAC Registry Server

The OpenAC issuer and revocation registries, served over HTTP with [Hono](https://hono.dev) instead of from a contract. This is the off-chain counterpart of [`solidity`](../solidity/README.md): the same trees, the same roots and the same acceptance rules, so a Show proof built against either one verifies the same way.

| Registry                      | Tree                                                 | Show output      | On-chain counterpart       | Built on                                                                                                     |
| ----------------------------- | ---------------------------------------------------- | ---------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `IssuerRegistryAuthority`     | SHA-256 LeanIMT of approved issuer keys              | `issuerRoot`     | `OpenACIssuerRegistry`     | [`@coordination-network/issuer-registry`](https://www.npmjs.com/package/@coordination-network/issuer-registry)         |
| `RevocationRegistryAuthority` | SHA-256 LeanIMT+ of revoked commitments, all issuers | `revocationRoot` | `OpenACRevocationRegistry` | [`@coordination-network/revocation-registry`](https://www.npmjs.com/package/@coordination-network/revocation-registry) |

Both libraries run here as the authority (the server that writes and publishes roots), and on holders as mirrors rebuilt from the server's leaves. Both use `sha256Scheme`, which matches `Sha256IssuerRegistry`, `Sha256Revocation` and the Show circuit.

## Trust model

On chain, everyone reads the same root from the contract. Off chain, verifiers trust the server operator for the current root, and a holder's synced tree is checked against the root the server serves with it. Holders download the whole tree and build proofs locally, so the server never learns which issuer or which commitment a holder proves against. It does see when verifiers check roots.

## Behaviour

Shared by both registries:

- **Root history.** A superseded root stays valid for `rootDuration` seconds (3600 by default), compared strictly, so `0` gives no grace. A root that becomes current again loses its stamp.
- **Max depth (issuer registry only).** An add that would make the issuer tree deeper than the Show circuit can prove is rejected (`MAX_DEPTH_EXCEEDED`), as `OpenACIssuerRegistry.MAX_DEPTH`. The default is 8 (256 issuers). The revocation registry has no cap, like the contract: a revocation is never refused, so past the Show `revocationMaxDepth` (10) holders can no longer present, rather than a revoked credential staying valid.
- **All or nothing.** A failed write, including a batch with one bad commitment, leaves the tree unchanged. A write only becomes visible once it has been saved.

Issuer registry:

- Leaves are `sha256(be32(pubKeyX) || be32(pubKeyY))`, i.e. `issuerCommitment(key)` in `openac-sdk`.
- The empty root `0` is never valid.
- `expireRoots` rejects every superseded root. Call it after removing a compromised issuer. As on chain, a root superseded in the same second as the expiry stays valid only if it was the current root at the expiry.

Revocation registry:

- **One registry for all issuers.** With one registry per issuer, the revocation root in a presentation would identify the issuer and undo issuer hiding.
- The empty root `0` is valid while current, and for `rootDuration` after the first revocation.
- The owner authorizes revokers, one per issuer, by id. Authorizing returns a bearer token, shown once. Authorizing again rotates the token.
- Each revoked commitment records its revoker (`revokedBy`). Only that revoker can unrevoke or update it, and only while it is still authorized. A deauthorized revoker's revocations stay in place.
- The owner cannot revoke unless it authorizes itself as a revoker.
- Only the owner can look up whether a revoker id is authorized, so the set of issuers with revocation rights is not public. `revokedBy` is still returned for revoked commitments, as on chain.

## Running the server

```bash
yarn
yarn build
ISSUER_OWNER_TOKEN=... REVOCATION_OWNER_TOKEN=... yarn start
```

A registry is served only when its owner token is set. Generate tokens with `node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"`.

| Variable                 | Default     | Purpose                                                       |
| ------------------------ | ----------- | ------------------------------------------------------------- |
| `ISSUER_OWNER_TOKEN`     |             | Owner token for the issuer registry (at least 16 characters)  |
| `REVOCATION_OWNER_TOKEN` |             | Owner token for the revocation registry                       |
| `PORT`, `HOST`           | `8787`, `127.0.0.1` | Listen address                                        |
| `DATA_DIR`               | `./data`    | `issuer-registry.json` and `revocation-registry.json`         |
| `ROOT_DURATION`          | `3600`      | Root grace period in seconds, for a new registry              |
| `ISSUER_MAX_DEPTH`       | `8`         | For a new issuer registry, at most 8 (the circuit limit) |
| `CORS_ORIGIN`            | `*`         | `Access-Control-Allow-Origin`; empty disables CORS            |

The server speaks plain HTTP. Put it behind TLS in any real deployment, since bearer tokens travel in headers. State files hold token hashes, never tokens. The tree is rehashed and checked on load.

To embed the server, call `createRegistryServer({ issuer, revocation })` with a `StateStore` per registry (`FileStore`, `MemoryStore`, or your own database). `createRegistryApp` takes the same options and returns the Hono app alone, to mount in another Hono app with `app.route()` or to run on another Hono runtime (the token helpers use `node:crypto`, which Bun and Deno also provide).

## HTTP API

Values are uint256s, returned as decimal strings. Requests may also use `0x` hex. Writes take `Authorization: Bearer <token>`.

| Method   | Path                              | Auth    | Body / result                                                       |
| -------- | --------------------------------- | ------- | ------------------------------------------------------------------- |
| `GET`    | `/issuer`                         |         | `{ root, depth, size, maxDepth, rootDuration, leaves }`             |
| `GET`    | `/issuer/root`                    |         | `{ root }`                                                          |
| `GET`    | `/issuer/roots/:root`             |         | `{ root, valid }`                                                   |
| `GET`    | `/issuer/commitments/:c`          |         | `{ commitment, isIssuer, index }`                                   |
| `POST`   | `/issuer/commitments`             | owner   | `{ commitments: [...] }` → `{ root }`                               |
| `PUT`    | `/issuer/commitments/:c`          | owner   | `{ newCommitment }` → `{ root }`                                    |
| `DELETE` | `/issuer/commitments/:c`          | owner   | → `{ root }`                                                        |
| `PUT`    | `/issuer/root-duration`           | owner   | `{ rootDuration }`                                                  |
| `POST`   | `/issuer/expire-roots`            | owner   | → `{ root }`                                                        |
| `GET`    | `/revocation`                     |         | `{ root, depth, size, rootDuration, leaves: [{ value, nextValue }] }` |
| `GET`    | `/revocation/root`                |         | `{ root }`                                                          |
| `GET`    | `/revocation/roots/:root`         |         | `{ root, valid }`                                                   |
| `GET`    | `/revocation/commitments/:c`      |         | `{ commitment, isRevoked, revokedBy }`                              |
| `POST`   | `/revocation/commitments`         | revoker | `{ commitments: [...] }` → `{ root }` (revoke)                      |
| `PUT`    | `/revocation/commitments/:c`      | revoker | `{ newCommitment }` → `{ root }` (update)                           |
| `DELETE` | `/revocation/commitments/:c`      | revoker | → `{ root }` (unrevoke)                                             |
| `GET`    | `/revocation/revokers/:id`        | owner   | `{ id, authorized }`                                                |
| `PUT`    | `/revocation/revokers/:id`        | owner   | `{ authorized }` → `{ id, authorized, token? }`                     |
| `PUT`    | `/revocation/root-duration`       | owner   | `{ rootDuration }`                                                  |
| `GET`    | `/health`                         |         | `{ ok, issuer, revocation }`                                        |

Errors are `{ error, message }`: `400 INVALID_INPUT`, `401 UNAUTHORIZED`, `403 FORBIDDEN`, `404 NOT_FOUND`, `405 METHOD_NOT_ALLOWED`, `409 MAX_DEPTH_EXCEEDED` (issuer adds), `413 PAYLOAD_TOO_LARGE`, `503 STORAGE_FAILED`.

`/issuer` and `/revocation` return every leaf (removed issuers as `0`, revocation tombstones included), like `getLeaf` on chain. Holders should not query `/revocation/commitments/:c` for their own commitment, since that tells the server which credential they hold.

## Client

`RegistryClient` wraps the API. With `openac-sdk`:

```ts
import { RegistryClient } from "@openac/registry-server"

const registry = new RegistryClient("https://registry.example")

// Holder: sync both trees, then prove locally.
const issuers = await registry.syncIssuerRegistry() // IssuerRegistry, root checked
const revoked = await registry.syncRevocationRegistry() // RevocationRegistry, root checked
const issuerProof = issuers.generateProof(issuerCommitment(issuerPublicKey))
// present(..., { issuerProof, revocation: { secret, registry: revoked } })

// Verifier
// verify(..., { isValidIssuerRoot: registry.isValidIssuerRoot, isValidRevocationRoot: registry.isValidRevocationRoot })

// Issuer registry owner
await new RegistryClient(url, { token: issuerOwnerToken }).addIssuers([issuerCommitment(newIssuerKey)])

// Revocation registry owner, then the issuer's revoker
const { token } = await new RegistryClient(url, { token: revocationOwnerToken }).setRevoker("issuer-a", true)
await new RegistryClient(url, { token }).revoke(computeRevocationCommitment(secret))
```

The authorities (`IssuerRegistryAuthority`, `RevocationRegistryAuthority`) can also be used in-process without the server, with `toJSON` / `fromJSON` for persistence.

## Tests

```bash
yarn test
```

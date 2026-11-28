# OpenAC revocation contracts

On-chain revocation for OpenAC credentials. An issuer revokes a credential by publishing its revocation commitment `v = sha256(be32(x) || be32(y) || be32(r) || be32(3))` to a SHA-256 [LeanIMT+](https://pse.dev/blog/lean-imt-plus-efficient-merkle-tree-for-membership-and-non-membership-proofs), where `(x, y)` is the issuer key and `r` the revocation value signed into the credential. Holders prove in the Show circuit that `v` is absent and output the tree root; verifiers accept the root with `isValidRoot`. Writes take `v` (`computeRevocationCommitment` in `openac-sdk`), not `r`.

Built on [`@coordination-network/contracts`](https://github.com/ethereum/coordination-network/tree/main/packages/contracts/src/revocation) (`Sha256Revocation`).

## Contracts

| Contract                   | Role                                                                                       |
| -------------------------- | ------------------------------------------------------------------------------------------ |
| `Sha256Revocation`         | Revocation service (from the package): trees, root history, per-registry admins.           |
| `OpenACRevocationRegistry` | One issuer's registry on that service. Only the issuer (owner, two-step transfer) writes.  |

## Usage

```bash
yarn
yarn compile
yarn test
yarn deploy --network sepolia   # SEPOLIA_RPC_URL, SEPOLIA_PRIVATE_KEY
```

**Revoking (issuer).** Writes take the predecessor's slot, computed off chain with [`@coordination-network/revocation-registry`](https://www.npmjs.com/package/@coordination-network/revocation-registry) and `sha256Scheme`:

```ts
import { RevocationRegistry, sha256Scheme } from "@coordination-network/revocation-registry"

const mirror = new RevocationRegistry(revokedCommitments, sha256Scheme)
await registry.revoke(commitment, mirror.lowLeafIndexOf(commitment))
```

**Syncing (holder).** Read every slot with `getLeaf(REGISTRY_ID, i)` on the service and rebuild with `RevocationRegistry.fromLeaves(leaves, sha256Scheme)`. Check `root` against `getRevocationRoot()` before proving.

**Verifying.** Pass `(root, issuer) => contractFor(issuer.jwk).isValidRoot(root)` as `isValidRevocationRoot` to the OpenAC SDK's `verify`, using the registry of the issuer the proof was built under. A superseded root stays valid for the registry's root duration (1 hour by default), so a revoked credential can still verify for that long.

# OpenAC Solidity

On-chain registries for OpenAC presentations. The Show circuit outputs two roots, and a verifier accepts a presentation only if both are valid on chain:

| Contract                   | Tree                                                   | Show output      | Built on                                                                                                 |
| -------------------------- | ------------------------------------------------------ | ---------------- | -------------------------------------------------------------------------------------------------------- |
| `OpenACIssuerRegistry`     | SHA-256 LeanIMT of approved issuer keys                | `issuerRoot`     | [`Sha256IssuerRegistry`](https://www.npmjs.com/package/@coordination-network/contracts)                  |
| `OpenACRevocationRegistry` | SHA-256 LeanIMT+ of revoked commitments, all issuers   | `revocationRoot` | [`Sha256Revocation`](https://github.com/ethereum/coordination-network/tree/main/packages/contracts/src/revocation) |

Each is a thin admin contract over a shared service that holds the tree and its root history. To run the registries without a chain, see [`registry-server`](../registry-server/README.md), which serves the same trees and roots over HTTP.

## Root limbs

The circuit outputs each root as two 128-bit limbs. Recombine before calling `isValidRoot`:

```
root = hi * 2^128 + lo
```

## Issuer hiding: `OpenACIssuerRegistry`

The Show circuit proves the credential's issuer is a leaf and outputs the tree root. A verifier only checks `isValidRoot(issuerRoot)`, so it learns that an approved issuer signed the credential, not which one.

```
commitment = sha256(be32(pubKeyX) || be32(pubKeyY) || be32(2))   // issuer's P-256 key, tag 2
```

This is `issuerCommitment(key)` from `openac-sdk`. Node hash is `sha256(left || right)`, so the tag makes a commitment a 768-bit hash input that no node shares; off chain use `new IssuerRegistry(commitments, sha256Scheme)`.

- Constructor: `(IIssuerRegistry service, uint256 maxDepth, uint256 rootDuration, address initialOwner)`. Creates the registry on `service` with itself as admin.
- Owner writes (`Ownable2Step`): `addIssuer`, `addIssuers`, `removeIssuer`, `updateIssuerCommitment`, `updateRootDuration`, `expireRoots`.
- Reads: `isValidRoot(root)`, `getIssuerRoot()`, `isIssuer(commitment)`.
- `MAX_DEPTH` (OpenAC: 8, i.e. 256 issuers): adds that would make the tree deeper revert with `MaxDepthExceeded`, so every issuer stays provable in the circuit.
- `removeIssuer` / `updateIssuerCommitment` take Merkle siblings: `registry.siblingNodesOf(commitment)` from the TS lib.
- A superseded root stays valid for `rootDuration` seconds. After removing a compromised issuer, call `expireRoots()`.
- Holders rebuild the tree from the service (`getLeaf`, `getIssuerTreeSize`) under `REGISTRY_ID`.

## Revocation: `OpenACRevocationRegistry`

An issuer revokes a credential by inserting its revocation commitment `v = sha256(be32(x) || be32(y) || be32(r) || be32(3))` into a SHA-256 [LeanIMT+](https://pse.dev/blog/lean-imt-plus-efficient-merkle-tree-for-membership-and-non-membership-proofs), where `(x, y)` is the issuer key and `r` the revocation value signed into the credential. Holders prove in the Show circuit that `v` is absent and output the tree root; verifiers accept the root with `isValidRoot(revocationRoot)`.

There is **one revocation registry for all issuers**. With one registry per issuer, the revocation root in a presentation would identify the issuer and undo issuer hiding.

- Constructor: `(IRevocation service, address initialOwner, uint256 rootDuration)`. Creates the registry on `service` with itself as admin.
- Owner writes (`Ownable2Step`): `revoke`, `revokeMany`, `unrevoke`, `updateRevocationCommitment`, `updateRootDuration`. The owner revokes on behalf of every issuer. Writes take the commitment `v` (`computeRevocationCommitment` in `openac-sdk`), not the signed value `r`.
- Reads: `isValidRoot(root)`, `getRevocationRoot()` (zero while empty, and root 0 is valid), `isRevoked(commitment)`.
- A superseded root stays valid for `rootDuration` seconds (1 hour by default), so a revoked credential can still verify for that long.

**Revoking (owner).** Writes take the predecessor's slot, computed off chain with [`@coordination-network/revocation-registry`](https://www.npmjs.com/package/@coordination-network/revocation-registry) and `sha256Scheme`, against the shared tree:

```ts
import { RevocationRegistry, sha256Scheme } from "@coordination-network/revocation-registry"

const mirror = new RevocationRegistry(revokedCommitments, sha256Scheme) // every issuer's revocations
await registry.write.revoke([commitment, mirror.lowLeafIndexOf(commitment)])
```

**Syncing (holder).** Read every slot with `getLeaf(REGISTRY_ID, i)` on the service and rebuild with `RevocationRegistry.fromLeaves(leaves, sha256Scheme)`. Check `root` against `getRevocationRoot()` before proving.

## Usage

```bash
yarn
yarn compile
yarn test
yarn deploy                                       # both registries, local in-process network
yarn hardhat ignition deploy ignition/modules/OpenAC.ts --network sepolia
```

`ignition/modules/OpenAC.ts` deploys both registries; `OpenACIssuerRegistry.ts` and `OpenACRevocationRegistry.ts` deploy one each. Ignition parameters (`maxDepth` = 8, `rootDuration` = 3600, `owner` = deployer, per module) can be overridden with `--parameters`. Sepolia needs `SEPOLIA_RPC_URL` and `SEPOLIA_PRIVATE_KEY` (env vars or `yarn hardhat keystore set`).

# OpenAC Solidity

On-chain issuer hiding for OpenAC. `OpenACIssuerRegistry` keeps OpenAC's approved issuers in one SHA-256 LeanIMT on a shared [`Sha256IssuerRegistry`](https://www.npmjs.com/package/@coordination-network/contracts) service. The Show circuit proves the credential's issuer is a leaf and outputs the tree root; a verifier only checks `isValidRoot(root)`, so it learns that an approved issuer signed the credential, not which one.

## Issuer commitment

```
commitment = sha256(be32(pubKeyX) || be32(pubKeyY))   // issuer's P-256 key
```

This is `sha256Hash2(x, y)` from `@coordination-network/issuer-registry`. Node hash is `sha256(left || right)`; off chain use `new IssuerRegistry(commitments, sha256Scheme)`.

## Root limbs

The circuit outputs the root as two 128-bit limbs. Recombine before calling `isValidRoot`:

```
root = hi * 2^128 + lo
```

## Contract

- Constructor: `(IIssuerRegistry service, uint256 maxDepth, uint256 rootDuration, address initialOwner)`. Creates the registry on `service` with itself as admin.
- Owner writes (`Ownable2Step`): `addIssuer`, `addIssuers`, `removeIssuer`, `updateIssuerCommitment`, `updateRootDuration`, `expireRoots`.
- Reads: `isValidRoot(root)`, `getIssuerRoot()`, `isIssuer(commitment)`.
- `MAX_DEPTH` (OpenAC: 8, i.e. 256 issuers): adds that would make the tree deeper revert with `MaxDepthExceeded`, so every issuer stays provable in the circuit.
- `removeIssuer` / `updateIssuerCommitment` take Merkle siblings: `registry.siblingNodesOf(commitment)` from the TS lib.
- A superseded root stays valid for `rootDuration` seconds. After removing a compromised issuer, call `expireRoots()`.
- Holders rebuild the tree from the service (`getLeaf`, `getIssuerTreeSize`) under `REGISTRY_ID`.

## Usage

```bash
yarn
yarn compile
yarn test
yarn deploy                                       # local in-process network
yarn hardhat ignition deploy ignition/modules/OpenACIssuerRegistry.ts --network sepolia
```

Ignition parameters (`maxDepth` = 8, `rootDuration` = 3600, `owner` = deployer) can be overridden with `--parameters`. Sepolia needs `SEPOLIA_RPC_URL` and `SEPOLIA_PRIVATE_KEY` (env vars or `yarn hardhat keystore set`).

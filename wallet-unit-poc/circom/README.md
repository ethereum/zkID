# Circom validation of JWT ES256 tokens
## Resources

- **PoC Documentation:** [JWT Docs (Notion)](https://www.notion.so/pse-team/Seediq-JWT-Docs-1f1d57e8dd7e80018655ccdc7332b1af)
- **Circuit Specifications:** [SPEC.md](./SPEC.md)
- **Demo Video:** [Loom Walkthrough](https://www.loom.com/share/83cebc44d54a47baae959a643475e9e2?sid=e7ec15c4-1ab6-4334-9830-c341d2d76e41)
- **Live Frontend:** [https://privacy-scaling-explorations.github.io/seediq-frontend/](https://privacy-scaling-explorations.github.io/seediq-frontend/)


## Repositories

- **Frontend Repository:** [seediq-frontend](https://github.com/privacy-scaling-explorations/seediq-frontend)
- **Circuits Repository:** [zkID (Circuits)](https://github.com/privacy-scaling-explorations/zkID)

note: This project uses [circomkit](https://github.com/erhant/circomkit) to compile, setup, prove, and verify Circom circuits

```

## Circuits

- `es256` – ECDSA signature verification (ES256)
- `jwt` – JWT validation circuit
- `show`: device binding, predicates, issuer hiding and revocation (`show_mdoc` without revocation)

### Issuer hiding

- `components/issuer-membership.circom`: proves the issuer key's leaf `sha256(be32(x) || be32(y) || be32(2))` is in a SHA-256 LeanIMT ([`@zk-kit/binary-merkle-root-sha256.circom`](https://www.npmjs.com/package/@zk-kit/binary-merkle-root-sha256.circom)) and outputs the root as `[hi, lo]` limbs. Prepare (`jwt`, `mdoc`) keeps the issuer key private and shares it with Show through `comm_W_shared`.

### Revocation

- `components/revocation-value-extractor.circom`: reads the signed `revocation_value` from the JWT payload. Every JWT credential must carry it.
- `components/revocation.circom`: `RevocationCheck(MAX_DEPTH)` derives the commitment `sha256(be32(x) || be32(y) || be32(r) || be32(3))` from the issuer key bits (canonical, from `IssuerMembership`) and the signed revocation value `r`, and proves its non-membership in a SHA-256 LeanIMT+ ([`@zk-kit/lean-imt-plus-sha256.circom`](https://www.npmjs.com/package/@zk-kit/lean-imt-plus-sha256.circom)), and outputs the root.
- `Show(..., maxIssuerDepth, revocationMaxDepth)`: `revocationMaxDepth = 0` disables revocation.
- There is a single revocation tree shared by all issuers. A per-issuer tree would make the revocation root identify the issuer and undo issuer hiding.

## Testing

You can test the circuits in two main ways:

### 1. Using circom_tester via typescript

```
yarn test
```

### 2. Using circomkit CLI

The project includes build scripts for each circuit:

```
bash scripts/build jwt # Runs full flow for jwt.circom
bash scripts/build all # Runs all circuits
```

These commands automatically compile the circuit, download ptau according circuit size,run the proving ceremony, generate proofs using the inputs from default.json, and verify the proofs in a single workflow.

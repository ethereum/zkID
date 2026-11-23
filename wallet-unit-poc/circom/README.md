# Circom validation of JWT ES256 tokens

> [!IMPORTANT]
> This code is a reference implementation. It has not been checked for production quality.
>
> Only an internal audit has been completed. The code has not had an external audit.

## Resources

- **PoC Documentation:** [JWT Docs (Notion)](https://www.notion.so/pse-team/Seediq-JWT-Docs-1f1d57e8dd7e80018655ccdc7332b1af)
- **Circuit Specifications:** [SPEC.md](./SPEC.md)
- **Demo Video:** [Loom Walkthrough](https://www.loom.com/share/83cebc44d54a47baae959a643475e9e2?sid=e7ec15c4-1ab6-4334-9830-c341d2d76e41)


## Repositories

- **Frontend Repository (archived):** [seediq-frontend](https://github.com/privacy-ethereum/seediq-frontend)

note: This project uses [circomkit](https://github.com/erhant/circomkit) to compile, setup, prove, and verify Circom circuits

```

## Circuits

- `es256` – ECDSA signature verification (ES256)
- `jwt` – JWT validation circuit

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

# zkID

zkID is the Ethereum Foundation's repository for OpenAC, an open design for anonymous credentials built on zero-knowledge proofs. It holds everything around OpenAC in one place: the paper, the protocol specifications, the circuits, the provers and SDKs, the wallet proofs of concept and the demos.

The repository is maintained by the Technical Foundations team, part of the Institutional cluster at the Ethereum Foundation. Guides, reports and other general resources about our work are at [publicsector.ethereum.foundation/resources](https://publicsector.ethereum.foundation/resources/).

> [!IMPORTANT]
> This code is a reference implementation. It has not been checked for production quality.
>
> Only an internal audit has been completed. The code has not had an external audit.

## Introduction

Digital identity credentials are usually presented by showing the issuer's signature. The signature is the same every time, so a holder who shows one credential to two verifiers can be linked across them, even when only a few attributes are disclosed.

OpenAC is designed to remove that link while leaving issuance as it is. The holder proves in zero knowledge that they hold a credential signed by the issuer, and reveals only the result of the verifier's policy, for example "over 18: true".

- It works with credentials that exist today. The issuer keeps signing with ECDSA P-256 and does not change its issuance flow.
- It needs no trusted setup.
- Proving runs on the holder's own device, including phones.
- It was designed with the European Digital Identity Architecture and Reference Framework (EUDI ARF) in mind. The paper maps the ARF requirements to the construction.

The paper is "OpenAC: Open Design for Transparent and Lightweight Anonymous Credentials", on [ePrint as 2026/251](https://eprint.iacr.org/2026/251). The source of its first version is in [`paper/`](./paper).

## How OpenAC works

A presentation is two proofs that are tied together.

| Proof | When it runs | What it proves |
| --- | --- | --- |
| Prepare | Once per credential | The issuer's signature over the credential is valid, and the claims were read from the signed payload. |
| Show | Once per presentation | The holder's device key signed the verifier's nonce, and the verifier's policy evaluates to the stated result over the credential's claims. |

The two proofs share a commitment to the same hidden values, so a verifier knows the Show proof is about the credential that Prepare checked. The slow proof (Prepare) is computed ahead of time and re-randomised for each presentation. The fast proof (Show) is the only one computed while the verifier waits.

A policy is a boolean expression over claims. Predicates compare a claim with a constant or with another claim using `<=`, `>=` or `==`, and combine with AND, OR and NOT. The design is described in [`generalized-predicates/`](./generalized-predicates).

The proofs use Spartan2 with Hyrax commitments. The circuits are written in Circom and compiled over the secq256r1 field, so the P-256 signature check is native arithmetic.

## What is in this repository

| Path | Contents |
| --- | --- |
| [`paper/`](./paper) | LaTeX source of the first version of the OpenAC paper. The current version is on ePrint. |
| [`specs/`](./specs) | Protocol specifications: `1/OPENAC`, `2/ZK-PROOF-OF-PERSONHOOD` and `3/ZK-AGE-VERIFICATION`. All three have status `raw`. |
| [`generalized-predicates/`](./generalized-predicates) | Design note for predicate proofs over credential attributes. |
| [`revocation/`](./revocation) | Design notes on privacy-preserving revocation and the LeanIMT+ Merkle tree. |
| [`wallet-unit-poc/circom/`](./wallet-unit-poc/circom) | The circuits: `jwt.circom`, `mdoc.circom`, `show.circom` and their components. |
| [`wallet-unit-poc/ecdsa-spartan2/`](./wallet-unit-poc/ecdsa-spartan2) | Rust prover and verifier with a command-line interface, and the desktop benchmarks. |
| [`wallet-unit-poc/openac-sdk/`](./wallet-unit-poc/openac-sdk) | TypeScript SDK for holders and verifiers. |
| [`wallet-unit-poc/mobile/`](./wallet-unit-poc/mobile) | Flutter wallet proof of concept for iOS and Android. |
| [`wallet-unit-poc/web-demo/`](./wallet-unit-poc/web-demo) | Browser demo that runs the full Prepare and Show pipeline. |
| [`wallet-unit-poc/openac-studio/`](./wallet-unit-poc/openac-studio) | OpenAC Studio, a guided integration designer and explainer. |

## Implementations of OpenAC

The same construction is implemented for several credential formats and several platforms. Not all of them are at the same stage.

### By credential format

| Variant | Credential and signature | Where | Stage |
| --- | --- | --- | --- |
| SD-JWT | SD-JWT signed with ES256 (ECDSA P-256) | `main`: circuits, Rust CLI, SDK, mobile app, web demo | Released in v5.0.0 |
| mdoc / mDL | ISO/IEC 18013-5 mobile driving licence | `main`: circuits and Rust CLI. See [`mdoc-spec.md`](./wallet-unit-poc/circom/docs/mdoc-spec.md) | Released in v5.0.0. Pull request [#107](https://github.com/ethereum/zkID/pull/107) (open) fixes linked verification of mdoc presentations. |
| RSA X.509 certificate | Certificate chain with RSA-2048 or RSA-4096, and a user signature with RSA-2048 | Branch [`RSA-X.509-Cert`](https://github.com/ethereum/zkID/tree/RSA-X.509-Cert), with prebuilt circuits, keys and bindings in the release "RSA-X.509-Cert (latest build)" | On a branch, not in `main`. Used by the Taiwan Citizen Digital Certificate examples for [web](https://github.com/ethereum/openac-taiwan-citizen-digital-certificate-web-example), [iOS](https://github.com/privacy-ethereum/openac-taiwan-citizen-digital-certificate-ios-example) and [Android](https://github.com/privacy-ethereum/openac-taiwan-citizen-digital-certificate-android-example). |
| RS256 JWT | Standalone RSA-2048 and RSA-4096 signature verification | See [`RSA_REFERENCE.md`](./wallet-unit-poc/RSA_REFERENCE.md) | Reference only. These circuits are not linked to Show and cannot be re-randomised. |
| Issuer hiding and revocation | SD-JWT | Branch [`feat/revocation-and-issuer-hiding`](https://github.com/ethereum/zkID/tree/feat/revocation-and-issuer-hiding) | In development, not merged. |

The SD-JWT Prepare circuit comes in four sizes, labelled 1k, 2k, 4k and 8k, for credentials of increasing length. Each size has its own keys. Show is the same for all four.

### By platform

| Platform | Path | Notes |
| --- | --- | --- |
| Command line (Rust) | [`wallet-unit-poc/ecdsa-spartan2/`](./wallet-unit-poc/ecdsa-spartan2) | Setup, prove, re-randomise, verify and benchmark, for SD-JWT and mdoc. |
| Node.js and browser (TypeScript) | [`wallet-unit-poc/openac-sdk/`](./wallet-unit-poc/openac-sdk) | SD-JWT only. Node 18 or later; the browser build uses WebAssembly. |
| iOS and Android (Flutter) | [`wallet-unit-poc/mobile/`](./wallet-unit-poc/mobile) | SD-JWT. Uses the Rust prover through mopro bindings. Has a walk-through screen and a benchmark screen. |
| Browser demo | [`wallet-unit-poc/web-demo/`](./wallet-unit-poc/web-demo) | SD-JWT. Runs the prover in WebAssembly. |

## Getting started

Each component has its own README with build steps. The order matters:

1. Compile the circuits in [`wallet-unit-poc/circom/`](./wallet-unit-poc/circom). The Rust crate does not build until the circuits are compiled.
2. Generate keys and run proofs with [`wallet-unit-poc/ecdsa-spartan2/`](./wallet-unit-poc/ecdsa-spartan2).
3. Build on top with the SDK, the mobile app or the web demo.

[`wallet-unit-poc/README.md`](./wallet-unit-poc/README.md) walks through the first two steps. To understand the design before building anything, start with the paper and [`specs/1-openac/`](./specs/1-openac).

## Benchmarks

- Desktop timings and proof sizes: [`wallet-unit-poc/ecdsa-spartan2/README.md`](./wallet-unit-poc/ecdsa-spartan2/README.md#latest-benchmark-results)
- Mobile timings: [`wallet-unit-poc/mobile/README.md`](./wallet-unit-poc/mobile/README.md)
- Comparison with other client-side proving systems: [ethereum/csp-benchmarks](https://github.com/ethereum/csp-benchmarks)

## Resources

- The paper: [OpenAC on ePrint (2026/251)](https://eprint.iacr.org/2026/251)
- The protocol specification: [`specs/1-openac/`](./specs/1-openac)
- General resources about our work, for governments and public institutions: [publicsector.ethereum.foundation/resources](https://publicsector.ethereum.foundation/resources/)

## Security

Please report security issues privately. See [`SECURITY.md`](./SECURITY.md).

## Contributing

Issues and pull requests are welcome. See [`CONTRIBUTING.md`](./CONTRIBUTING.md) and the [Code of Conduct](./CODE_OF_CONDUCT.md).

## History

This work started in the zkID team at Privacy Stewards of Ethereum (PSE), and the repository was first published as `privacy-ethereum/zkID`. Old links redirect here. Some older documents in the repository still refer to PSE.

## License

[MIT](./LICENSE). Copyright Ethereum Foundation.

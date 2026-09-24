## Supported Verifiable Credentials

This PoC currently supports the following credential formats:

| Format | Status | Reference |
| --- | --- | --- |
| **SD-JWT** (ES256) | Implemented | [openac-sdk](./openac-sdk/README.md) |
| **mDOC / mDL** (ISO 18013-5) | Implemented | [circom/docs/mdoc-spec.md](./circom/docs/mdoc-spec.md) |

### Call for Feedback

We're actively scoping support for additional credential formats (e.g. W3C VC-JWT, BBS+, EUDI ARF profiles). If your use case needs a format not listed above, please open an issue at [privacy-ethereum/zkID/issues](https://github.com/privacy-ethereum/zkID/issues)

## Setup

### Step 1: Compile Circom Circuits

Compile the circom circuits with secq256r1 as native field:

```sh
pnpm install
pnpm compile:jwt
pnpm compile:ecdsa
```

This creates a build folder containing R1CS and WASM files for circuits.

### Step 2: Setup Keys for Circuits

Setup keys for ECDSA circuit:

```sh
RUST_LOG=info cargo run --release -- setup_ecdsa
```

Setup keys for JWT circuit:

```sh
RUST_LOG=info cargo run --release -- setup_jwt
```

### Step 3: Run Circuits

Run ECDSA circuit:

```sh
RUST_LOG=info cargo run --release -- prove_ecdsa
```

Run JWT circuit:

```sh
RUST_LOG=info cargo run --release -- prove_jwt
```

## Benchmarks

This section contains comprehensive benchmark results for zkID wallet proof of concept, covering both desktop and mobile implementations.

### Desktop Benchmarks (ecdsa-spartan2)

See [ecdsa-spartan2/README.md](./ecdsa-spartan2/README.md#latest-benchmark-results) for up-to-date timings and sizes across all circuit sizes (1k/2k/4k/8k).

### RSA Verifier Circuits (Reference)

For RS256 (RSA-based) JWT verification, standalone RSA-2048 and RSA-4096 verifier circuits are available as a PoC on the [`feat/rsa-verifier-circuit`](https://github.com/moven0831/zkID/tree/feat/rsa-verifier-circuit) branch. See [RSA_REFERENCE.md](./RSA_REFERENCE.md) for circuit specification, build commands, and benchmarks.

### Mobile Benchmarks

For the reproduction of mobile benchmarks, please check the [OpenAC mobile app directory](/wallet-unit-poc/mobile/)

#### Prepare Circuit (Mobile)

- Payload Size: 1920 Bytes
- Peak Memory Usage for Proving: 2.27 GiB

|    Device    | Setup (ms) | Prove (ms) | Reblind (ms) | Verify (ms) |
|:------------:|:----------:|:----------:|:------------:|:-----------:|
|  iPhone 17   |    3254    |    2102    |     884      |     137     |
| Pixel 10 Pro |    9282    |    5161    |     1732     |     318     |

### Show Circuit Timing

The Show circuit has constant performance regardless of JWT payload size.
- Peak Memory Usage for Proving: 1.96 GiB

|    Device    | Setup (ms) | Prove (ms) | Reblind (ms) | Verify (ms) |
|:------------:|:----------:|:----------:|:------------:|:-----------:|
|  iPhone 17   |     43     |     85     |      30      |     13      |
| Pixel 10 Pro |     99     |    308     |     130      |     65      |

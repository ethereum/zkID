# ecdsa-spartan2

Spartan2-based proving CLI for the zkID wallet PoC. It produces and verifies a
two-stage split proof — `prepare` (the JWT/ES256 circuit) and `show` (the
device-binding + generalized predicate circuit) — against the Circom inputs
in `../circom/inputs/`.

## Prerequisites

- Rust
- A C++ toolchain (clang/g++, make) — needed by `witnesscalc-adapter` to
  link the Circom witness generators into the binary
- Circom circuits must already be compiled. From the repo root:

```sh
  cd ../circom
  pnpm install
  pnpm compile:all          # compiles jwt + jwt_1k/2k/4k/8k + show + ecdsa
```

## Build

```sh
cargo build --release
```

The first build is slow (~15 min) because `witnesscalc-adapter` compiles each
`jwt_*.cpp` (30-44 MB) into a static library. Incremental rebuilds are seconds.

## Run the pipeline

The CLI is `cargo run --release -- <prepare|show> <action> --size <Nk>`.
Sizes are `1k | 2k | 4k | 8k`. Each size has its own keys/artifacts in `./keys/`.

```sh
SIZE=1k

# 1. One-time setup per size (slow, writes large proving/verifying keys)
cargo run --release -- prepare setup --size $SIZE --input ../circom/inputs/jwt/$SIZE/default.json
cargo run --release -- show    setup --size $SIZE --input ../circom/inputs/show/$SIZE/default.json

# 2. Per-presentation flow
cargo run --release -- generate_shared_blinds --size $SIZE
cargo run --release -- prepare prove   --size $SIZE --input ../circom/inputs/jwt/$SIZE/default.json
cargo run --release -- prepare reblind --size $SIZE
cargo run --release -- show    prove   --size $SIZE --input ../circom/inputs/show/$SIZE/default.json
cargo run --release -- show    reblind --size $SIZE

# 3. Verify
cargo run --release -- prepare verify --size $SIZE
cargo run --release -- show    verify --size $SIZE
# → expressionResult: true
```

## One-shot benchmark

Runs the entire pipeline (setup → prove → reblind → verify) for one size and
prints a timings/sizes table:

```sh
cargo run --release -- benchmark --size 1k --input ../circom/inputs/jwt/1k/default.json
```

Or run all four sizes back-to-back (reuses keys already on disk; run `benchmark`
once per size first if you've never set them up):

```sh
cargo run --release -- benchmark-all
```

## Latest benchmark results

MacBook Pro M5, 24 GB RAM. Generated against the current generalized-predicates
circuits (`Show(2, 2, 8, 64)` + `JWT(maxMsg, ...)`) with the example predicate
`roc_birthday <= 1070101`.

### Timings (ms)

| Step            |    1k |    2k |    4k |    8k |
| --------------- | ----: | ----: | ----: | ----: |
| Prove Prepare   | 1,119 | 1,617 | 3,344 | 6,999 |
| Reblind Prepare |   337 |   638 | 1,257 | 2,662 |
| Prove Show      |    57 |    59 |    58 |    74 |
| Reblind Show    |    26 |    24 |    25 |    25 |
| Verify Prepare  |   740 | 1,170 | 2,229 | 4,769 |
| Verify Show     |    19 |    18 |    18 |    19 |

### Sizes

| Artifact            |        1k |        2k |        4k |          8k |
| ------------------- | --------: | --------: | --------: | ----------: |
| Prepare Proving Key | 257.22 MB | 407.18 MB | 773.90 MB | 1,512.03 MB |
| Show Proving Key    |   2.96 MB |   2.96 MB |   2.96 MB |     2.96 MB |
| Prepare Proof       |  75.93 KB | 109.41 KB | 175.90 KB |   308.38 KB |
| Show Proof          |  40.51 KB |  40.51 KB |  40.51 KB |    40.51 KB |

The Show circuit is constant across sizes (it doesn't see the JWT). Prepare
scales roughly linearly with the JWT message length.

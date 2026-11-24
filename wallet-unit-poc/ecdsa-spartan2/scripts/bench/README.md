# OpenAC+ benchmarks

Scripts that measure the OpenAC+ prototype and rebuild every paper table and figure from the raw rows.
The row formats are in [SCHEMA.md](SCHEMA.md).

## What is measured

- **Mac, per config:** Prepare and Show proving, verify, key and witness sizes, circuit shapes, peak memory. Binary: `openac_bench`.
- **Registries (Node):** issuer and revocation tree operations, snapshots, bandwidth. Script: `circom/scripts/benchmarks/registry-bench.ts`.
- **End to end:** composed wallet flows from the stage timings above.
- **Phones:** the same Prepare, Show and verify steps on an iPhone and an Android phone.

Raw rows and generated output go to `$OPENACPLUS_BENCH_ROOT`, never into git. `analysis/` turns them into `T*.tex`, `F*.tex`, `F*.pdf`, `F*.csv`, `checks.md`, `fits.md` and `provenance.csv`.

## Prerequisites

- Rust (the toolchain the repo builds with).
- Node with yarn 4 (`packageManager` in `circom/package.json`).
- `circom`, on the `PATH`.
- Python 3 with `matplotlib`, needed for the figure PDFs and for the analysis tests. A venv is fine (`python3 -m venv v && v/bin/pip install matplotlib`, then run the analysis with `v/bin/python`).
- For the `F*.tex` figures, the paper needs `\usepackage{pgfplots}`. Each file sets `compat=1.18` itself and can be `\input` inside `figure` or `figure*`. They compile with tectonic.
- `/usr/bin/time` (macOS), used for peak memory.

## Worktrees and paths

One git worktree per config. `combined` is the branch you clone; the other five are added next to it. `headline` is `combined` plus the D_rev 20 change only.

```
export OPENACPLUS_WORKTREES=<dir that will hold the six worktrees>
export OPENACPLUS_BENCH_ROOT=<dir outside any git tree; it may start empty>
mkdir -p "$OPENACPLUS_WORKTREES"

git worktree add "$OPENACPLUS_WORKTREES/combined"   bench/openacplus/combined
git worktree add "$OPENACPLUS_WORKTREES/headline"   bench/openacplus/headline
git worktree add "$OPENACPLUS_WORKTREES/main"       bench/openacplus/main
git worktree add "$OPENACPLUS_WORKTREES/issuer"     bench/openacplus/issuer
git worktree add "$OPENACPLUS_WORKTREES/revocation" bench/openacplus/revocation
git worktree add "$OPENACPLUS_WORKTREES/v1"         bench/openacplus/v1   # based on tag v1.0.0
```

The drivers look a config up as `$OPENACPLUS_WORKTREES/<config>`. The `variant` cells are built from `combined`. They exit with a message if either variable is unset, or if the root sits inside a git work tree. Keep every worktree clean while measuring. `refs.json` lists the expected SHAs and r1cs hashes.

Where each command runs:

| Command | Directory |
|---|---|
| Python drivers (`stage*.py`, `run_matrix.py`, `peakmem.py`, `shape_all.py`, `constraints.py`) and `analysis/analyze.py` | `$OPENACPLUS_WORKTREES/combined/wallet-unit-poc/ecdsa-spartan2/scripts/bench` |
| `yarn`, `npx tsx` (registry, variants, inputs) | `<worktree>/wallet-unit-poc/circom` |
| `cargo build` | `<worktree>/wallet-unit-poc/ecdsa-spartan2` |

## Build

In every worktree (`v1 main issuer revocation combined headline`), install, compile the circuits and build the binary:

```
for c in v1 main issuer revocation combined headline; do
  W="$OPENACPLUS_WORKTREES/$c/wallet-unit-poc"
  (cd "$W/circom" && yarn install --immutable && yarn compile:all)
  (cd "$W/ecdsa-spartan2" && cargo build --release --bin openac_bench)
done
```

`yarn compile:all` runs circom and takes a long time. Do not run `target/release/openac_bench` directly: it fails with a dylib rpath error. Staging copies the binary together with its dylibs, and every measurement uses that staged copy.

**Inputs.** Use the tracked `wallet-unit-poc/circom/inputs/{jwt,show}/<size>/default.json` as they are. Never run `yarn generate:inputs` in a measurement worktree: it rewrites those tracked files. If you did, restore them with `git checkout -- wallet-unit-poc/circom/inputs`. Only the headline's seeded inputs are generated, and they are written outside git (next section).

**Keys.** Staging copies keys from `<worktree>/wallet-unit-poc/ecdsa-spartan2/keys/<size>_*.key`, so set them up first. `keys/` is in `ecdsa-spartan2/.gitignore`. The package has two binaries, so `--bin ecdsa-spartan2` is required. These are the sizes each config stages:

| Config | Sizes |
|---|---|
| `v1`, `combined` | 1k, 2k, 4k, 8k |
| `main`, `issuer`, `revocation` | 1k, 2k |
| `headline` | 1k, 2k |

On branches that include PR #115 (`main`), setup also writes `*_verifying.digest` sidecars, staging copies them, and the `vk_digest` step is then near zero.

From each worktree's `wallet-unit-poc/ecdsa-spartan2`, for every size `<S>` in its row:
```
cargo run --release --bin ecdsa-spartan2 -- show setup --size <S> --input ../circom/inputs/show/<S>/default.json
cargo run --release --bin ecdsa-spartan2 -- prepare setup --size <S> --input ../circom/inputs/jwt/<S>/default.json
```
The `headline` Show keys use the headline worktree's inputs.
```
cargo run --release --bin ecdsa-spartan2 -- show setup --size 1k --input "$OPENACPLUS_BENCH_ROOT/laptop/inputs/headline/show-1k.json"
cargo run --release --bin ecdsa-spartan2 -- show setup --size 2k --input "$OPENACPLUS_BENCH_ROOT/variants/headline/show-2k.json"
```
Make those two files first (below). The headline Prepare setup uses the tracked default JWT input like the other configs.

**Headline and variant inputs.** Once, from `combined/wallet-unit-poc/circom` (the first two lines from the `headline` worktree, since they read that tree's compiled JWT wasm). The population matches the registry bench (256 issuers, 1,046,528 revoked).

```
npx tsx src/generate-inputs.ts --size 2k --issuers 256 --revoked 1046528 --seed 1 --out "$OPENACPLUS_BENCH_ROOT/variants/headline/show-2k.json"
npx tsx src/generate-inputs.ts --size 1k --issuers 256 --revoked 1046528 --seed 1 --out "$OPENACPLUS_BENCH_ROOT/laptop/inputs/headline/show-1k.json"
npx tsx scripts/benchmarks/run-sweep.ts            # compiles the sweep cells, writes variants/shape.jsonl
npx tsx scripts/benchmarks/build-inputs.ts         # Show inputs and witnesses, variants/inputs.jsonl
npx tsx scripts/benchmarks/build-jwt-inputs.ts     # the N = 8 and 16 Prepare inputs
```

Each `--out X.json` also writes `X.jwt.json` and `X.roots.json`, the three files staging reads. `run-sweep.ts --list` and `build-inputs.ts --list` show the cells.

## Run

**1. Shapes and staging.** Staging copies each cell's binary, dylibs, keys, inputs and meta under `$OPENACPLUS_BENCH_ROOT/laptop/stage/`.
```
python3 shape_all.py --worktree "$OPENACPLUS_WORKTREES/combined" --config combined   # once per config
python3 constraints.py --config combined --circom-dir "$OPENACPLUS_WORKTREES/combined/wallet-unit-poc/circom" \
  --out "$OPENACPLUS_BENCH_ROOT/laptop/constraints.jsonl"   # once for each of main, issuer, revocation, combined
python3 stage_all.py
python3 stage_generic_all.py
```
`stage_all.py` takes the groups `chain` and `headline`, and `--only CELL [CELL ...]` to stage single cells; `--only` needs a group, for example `python3 stage_all.py chain --only A1-combined-2k`. `stage_generic_all.py` also takes `--only CELL ...`. A selected cell needs only its own worktree.

**2. Smoke run.** One short visit, written under `laptop/smoke/` and marked `smoke: true`. Check it before spending hours.
```
python3 run_matrix.py --smoke --no-gate --run-id smoke-$(date +%Y%m%d) --warm 1 --visits 1 matrices/A1.json --only A1-combined-2k
python3 run_matrix.py --dry-run --run-id w1 matrices/A1.json matrices/A2.json   # visit order and time estimate
```
Matrix files go before `--only`, because `--only` takes many cell ids. The smoke passes when every proving or verifying `ITER` row has `ok: true` and the `DONE` row shows `errors: 0`. Key-load rows (`key_load_prepare`, `key_load_show`, `load_keys_total`) carry no `ok`.

**3. Window 1** (about 2 h) and **window 2** (about 4 h). Rows go to `laptop/runs/<run-id>/`.
```
python3 run_matrix.py --run-id w1-$(date +%Y%m%d) matrices/A1.json matrices/A2.json
python3 run_matrix.py --run-id w2-$(date +%Y%m%d) matrices/S-B.json matrices/S-D.json matrices/S-MT.json \
  matrices/S-N.json matrices/S-P.json matrices/W.json matrices/X2.json matrices/L5.json
```
Run the analysis after window 1 (step 6). Every proving or verifying `ITER` row should be `ok` (key-load rows carry no `ok`), and the gates in `checks.md` should pass before window 2 starts.

**4. Peak memory.** `run_matrix.py` does not run these cells. `matrices/PM.json` lists them and the runs each needs, and the `--final` gate reads it. `--config` is the stage directory name.
```
python3 peakmem.py --config main --cell A1-main-2k --runs 3
python3 peakmem.py --config headline --cell A1-headline-2k --runs 3
```

**5. Registry and end-to-end runs.** From `combined/wallet-unit-poc/circom`, with `NODE_OPTIONS=--expose-gc`. The registry bench takes one population per process (`--pops`). Its defaults are revocation 1024, 32768 and 1,046,528, and issuer 256 and 65,536 (the larger one is beyond the built circuit). Add `--smoke` to any of these for a quick check.
```
export NODE_OPTIONS=--expose-gc
for p in 256 65536 1024 32768 1046528; do npx tsx scripts/benchmarks/registry-bench.ts --pops $p; done
for k in 1 100 1000; do
  npx tsx scripts/benchmarks/e2e-registry.ts --stage "$OPENACPLUS_BENCH_ROOT/laptop/stage/headline/A1-headline-2k" --k $k
done
```
`registry-bench.ts` writes `$OPENACPLUS_BENCH_ROOT/registry/registry.jsonl`. `e2e-registry.ts` writes the end-to-end rows to `$OPENACPLUS_BENCH_ROOT/e2e/` and its registry rows to `$OPENACPLUS_BENCH_ROOT/registry/`. On the `bench/openacplus/registry-server` branch only the registry bench subset exists.

**6. Analysis.**
```
PY=<python with matplotlib, e.g. your venv's bin/python>
$PY analysis/analyze.py --root "$OPENACPLUS_BENCH_ROOT" --out "$OPENACPLUS_BENCH_ROOT/out"
$PY analysis/analyze.py --root "$OPENACPLUS_BENCH_ROOT" --out "$OPENACPLUS_BENCH_ROOT/out" --final
```
The analysis needs a Python with matplotlib; a bare `python3` without it fails.
`--root` defaults to `$OPENACPLUS_BENCH_ROOT`, and `--matrices` to `../matrices`. Without `--final`, missing data is skipped. With it, every gate must pass (visit counts, peak memory, provenance, phone checks, GC flag, expected phone sessions) or the exit code is 1. Read `checks.md` first. Reruns on the same rows give identical files.

Tests: `cd analysis && $PY -m unittest`. The driver tests: `python3 -m unittest discover tests` from this directory.

## Quiet-machine rules

- AC power, lid open, no Xcode, Android Studio or browsers.
- Nothing else compiling or testing. Check with `ps -Ao %cpu,command -r | head`.
- `run_matrix.py` runs an idle gate before every visit: no `cargo`, `rustc` or emulator running, no `gradle`, `flutter` or `circom` above 5% CPU, total CPU under 100%, nominal thermal pressure. A gate that does not clear within its timeout fails the visit. Do not use `--no-gate` outside smoke runs.
- Run Node producers from clean trees with `--expose-gc`.
- A visit that overlaps other work is untrusted. Move that run aside and redo it.

## Phones

- Access to the Developer Device Platform (DDP) is needed. Each submit costs device time, so ask before submitting.
- The mobile app and `bench_host` come from the PR #115 mobile tree. It is not part of these branches.
- Protocol: 12 warm iterations with a 3 s cooldown. This keeps the test run under the DDP iPhone limit of about 5 minutes; a whole session, setup included, takes about 6 minutes.
- After each session, check the proofs and the roots, then record a `PHONECHECK` row. `--final` needs one per session.
- For an iOS-versus-Android comparison, use a pair of phones matched on Geekbench score and RAM.

## Never commit

Do not commit r1cs files, keys, witnesses, staged binaries, inputs or result rows. They are large, and the keys and inputs are generated locally. Keep them under `$OPENACPLUS_BENCH_ROOT`. The only data in git is the small synthetic fixtures under `analysis/fixtures`.

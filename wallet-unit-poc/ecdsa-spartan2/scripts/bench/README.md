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
- Python 3. `matplotlib` is needed for the figure PDFs and for the analysis tests.
- `/usr/bin/time` (macOS), used for peak memory.

## Worktrees and paths

One git worktree per config, all under `OPENACPLUS_WORKTREES`:

| Directory | Branch |
|---|---|
| `v1` | `bench/openacplus/v1`, on tag `v1.0.0` |
| `main` | `bench/openacplus/main` |
| `issuer` | `bench/openacplus/issuer` |
| `revocation` | `bench/openacplus/revocation` |
| `combined` | `bench/openacplus/combined` |
| `headline` | `bench/openacplus/headline` |

```
export OPENACPLUS_WORKTREES=<dir with the six worktrees>
export OPENACPLUS_BENCH_ROOT=<empty dir outside any git tree>
```

The scripts refuse a root that sits inside a git work tree. Build each worktree as in `ecdsa-spartan2/README.md` (`yarn compile:all`, then `cargo build --release`) and keep it clean while measuring.

## Run

Run the Python drivers from `combined/wallet-unit-poc/ecdsa-spartan2/scripts/bench`.

**1. Stage.** Copies each cell's binary, keys, inputs and meta under `$OPENACPLUS_BENCH_ROOT/laptop/stage/`.
```
python3 stage_all.py
python3 stage_generic_all.py
```

**2. Smoke run.** One short visit, written under `laptop/smoke/` and marked `smoke: true`. Check it before spending hours.
```
python3 run_matrix.py --smoke --no-gate --run-id smoke-$(date +%Y%m%d) --warm 1 --visits 1 matrices/A1.json
python3 run_matrix.py --dry-run --run-id w1 matrices/A1.json matrices/A2.json   # visit order and time estimate
```

**3. Window 1** (about 2 h) and **window 2** (about 4 h). Rows go to `laptop/runs/<run-id>/`.
```
python3 run_matrix.py --run-id w1-$(date +%Y%m%d) matrices/A1.json matrices/A2.json
python3 run_matrix.py --run-id w2-$(date +%Y%m%d) matrices/S-B.json matrices/S-D.json matrices/S-MT.json \
  matrices/S-N.json matrices/S-P.json matrices/W.json matrices/X2.json matrices/L5.json
```
Run the analysis after window 1 (see below). Every `ITER` row should be `ok` and the gates in `checks.md` should pass before window 2 starts.

**4. Peak memory.** `run_matrix.py` does not run these cells. `--config` is the stage directory name.
```
python3 peakmem.py --config main --cell A1-main-2k --runs 3
python3 peakmem.py --config headline --cell A1-headline-2k --runs 3
```

**5. Registry run.** From a clean checkout of the registry bench branch, in `wallet-unit-poc/circom`. One population per process; `--pops` keeps the populations listed. Defaults are 2^10, 2^15 and about 2^20 for revocation, 256 and 65,536 for issuer.
```
export NODE_OPTIONS=--expose-gc
for p in 1024 32768 1046528; do npx tsx scripts/benchmarks/registry-bench.ts --pops $p; done
npx tsx scripts/benchmarks/registry-bench.ts --pops 256,65536
npx tsx scripts/benchmarks/e2e-registry.ts --stage "$OPENACPLUS_BENCH_ROOT/laptop/stage/headline/A1-headline-2k" --k 1
```
Repeat the last line with `--k 100` and `--k 1000`. Rows go to `$OPENACPLUS_BENCH_ROOT/registry/`. Add `--smoke` for a quick check.

**6. Analysis.**
```
python3 analysis/analyze.py --root "$OPENACPLUS_BENCH_ROOT" --out "$OPENACPLUS_BENCH_ROOT/out"
python3 analysis/analyze.py --root "$OPENACPLUS_BENCH_ROOT" --out "$OPENACPLUS_BENCH_ROOT/out" --final
```
`--root` defaults to `$OPENACPLUS_BENCH_ROOT`. Without `--final`, missing data is skipped. With it, every gate must pass (visit counts, peak memory, provenance, phone checks, GC flag, expected phone sessions) or the exit code is 1. Read `checks.md` first. Reruns on the same rows give identical files.

Tests: `cd analysis && python3 -m unittest`.

## Quiet-machine rules

- AC power, lid open, no Xcode, Android Studio or browsers.
- Nothing else compiling or testing, including other Claude sessions and agent teams. Check with `ps -Ao %cpu,command -r | head`.
- `run_matrix.py` runs an idle gate before every visit: no `cargo`, `rustc` or emulator running, no `gradle`, `flutter` or `circom` above 5% CPU, total CPU under 100%, nominal thermal pressure. A gate that does not clear within its timeout fails the visit. Do not use `--no-gate` outside smoke runs.
- Run Node producers from clean trees with `--expose-gc`.
- A visit that overlaps other work is untrusted. Move that run aside and redo it.

## Phones

- Access to the Developer Device Platform (DDP) is needed. Each submit costs device time, so ask before submitting.
- The mobile app and `bench_host` come from the PR #115 mobile tree. It is not part of these branches.
- Protocol: 12 warm iterations with a 3 s cooldown. The first plan, 20 warm with 10 s, ran over 20 minutes per session and hit a limit of about 5 minutes of test time on DDP iPhones. Sessions now take about 6 minutes.
- After each session, check the proofs and the roots, then record a `PHONECHECK` row. `--final` needs one per session.
- For an iOS-versus-Android comparison, use a pair of phones matched on Geekbench score and RAM.

## Never commit

Do not commit r1cs files, keys, witnesses, staged binaries, inputs or result rows. They are large, and the keys and inputs are generated locally. Keep them under `$OPENACPLUS_BENCH_ROOT`. The only data in git is the small synthetic fixtures under `analysis/fixtures`.

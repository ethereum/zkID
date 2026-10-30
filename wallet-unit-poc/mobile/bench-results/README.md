# Android bench results

Ten physical Android phones on Google's Developer Device Platform, from 4 GB budget phones to
flagships, ran this branch's harness (the "Host-driven Android benchmark" section of
[`../README.md`](../README.md)) on 28 and 30 October 2026. Every number below comes from the files in
this directory.

- 28 October, [`scripts/bench_workload.json`](../scripts/bench_workload.json): Show alone
  (`openac-show`), Prepare (`openac-prepare`) and a full presentation (`openac-present`: Show prove,
  then re-randomizing the Prepare and Show proofs), with proving keys pushed from the host.
- 30 October, [`scripts/bench_workload_primitives.json`](../scripts/bench_workload_primitives.json):
  CSP's SHA-256 over 2 KB, ported to the Spartan2 fork, as run `openac-sha256`.

Each run is a fresh app process. [`contract_bench.dart`](../flutter/integration_test/contract_bench.dart)
runs iteration 0 cold (it loads the keys from storage) and then five warm iterations, 10 s apart,
and reads each step's peak memory, VmHWM after a reset through `/proc/self/clear_refs`. The timed
calls are `prove_prepare_loaded`, `prove_show_loaded`, `prove_sha256_loaded` and `present_loaded`
in [`src/lib.rs`](../src/lib.rs). The last proofs of every run that finished were pulled and
verified on a laptop with `scripts/verify_device_proofs.sh`.

## Per phone

Cold is iteration 0, including loading; warm is the median of the five warm iterations; peak
is the highest VmHWM across the run's iterations. `analysis.md` has the tier medians beside
the laptop predictions they were checked against, the phones, and proof sizes.

### Prepare and presentation, 28 October

| Phone | Tier | Prepare: cold s | warm s | peak MiB | Presentation: cold s | warm s | peak MiB |
|---|---|---|---|---|---|---|---|
| Galaxy A06 | budget | killed | - | - | 11.2 | 6.18 | 1,975 |
| Infinix SMART 8 | budget | 35.3 | 33.5 | 1,519 † | 15.8 | 12.1 | 1,316 † |
| moto g05 | budget | 14.6 | 10.2 | 1,832 | 11.4 | 7.02 | 1,705 |
| Galaxy A35 | mid | 5.14 | 3.37 | 1,840 | 4.91 | 2.69 | 1,712 |
| Galaxy A55 | mid | 4.22 | 2.90 | 1,941 | 4.11 | 2.26 | 1,802 |
| Pixel 8a | mid | 5.37 | 4.38 | 1,861 | 3.90 | 2.52 | 1,765 |
| Pixel 9 Pro | flagship | 4.42 | 3.62 | 1,874 | 3.46 | 2.24 | 1,777 |
| Galaxy S23 Ultra | flagship | 2.71 | 1.88 | 2,861 | 2.84 | 1.53 | 2,008 |
| Pixel 11 Pro | flagship | 4.19 | 3.41 | 1,866 | 3.14 | 1.86 | 1,771 |
| Galaxy S26+ | flagship | 2.10 | 1.53 | 1,867 | 2.16 | 1.18 | 1,770 |

### Presentation steps, 28 October

The steps of the presentation above. A step's cold time leaves out loading, which counts only in
the presentation's total, and a step's peak includes both proving keys and the Prepare data
already in memory, which is why Show prove peaks far higher here than Show alone below.

| Phone | Tier | Show prove: cold s | warm s | peak MiB | Prepare re-randomize: cold s | warm s | peak MiB | Show re-randomize: cold s | warm s | peak MiB |
|---|---|---|---|---|---|---|---|---|---|---|
| Galaxy A06 | budget | 0.55 | 0.51 | 1,439 | 5.88 | 5.35 | 1,975 | 0.30 | 0.26 | 1,949 |
| Infinix SMART 8 | budget | 3.44 | 3.69 | 615 † | 7.25 | 7.24 | 1,316 † | 1.15 | 1.14 | 996 † |
| moto g05 | budget | 0.69 | 0.69 | 733 | 6.03 | 5.91 | 1,705 | 0.30 | 0.31 | 697 |
| Galaxy A35 | mid | 0.27 | 0.26 | 735 | 2.42 | 2.28 | 1,712 | 0.10 | 0.11 | 704 |
| Galaxy A55 | mid | 0.19 | 0.20 | 783 | 2.00 | 1.94 | 1,802 | 0.09 | 0.09 | 778 |
| Pixel 8a | mid | 0.34 | 0.49 | 755 | 1.76 | 1.80 | 1,765 | 0.17 | 0.19 | 749 |
| Pixel 9 Pro | flagship | 0.30 | 0.42 | 766 | 1.58 | 1.62 | 1,777 | 0.16 | 0.16 | 760 |
| Galaxy S23 Ultra | flagship | 0.15 | 0.18 | 1,762 | 1.33 | 1.26 | 2,008 | 0.07 | 0.07 | 2,008 |
| Pixel 11 Pro | flagship | 0.35 | 0.32 | 756 | 1.32 | 1.37 | 1,771 | 0.12 | 0.14 | 749 |
| Galaxy S26+ | flagship | 0.10 | 0.12 | 755 | 1.00 | 0.99 | 1,770 | 0.04 | 0.05 | 749 |

### Show alone, 28 October, and single check, 30 October

| Phone | Tier | Show: cold s | warm s | peak MiB | Spartan2 SHA-256, 2 KB: cold s | warm s | peak MiB |
|---|---|---|---|---|---|---|---|
| Galaxy A06 | budget | 0.69 | 0.48 | 275 | 4.39 | 2.93 | 1,359 |
| Infinix SMART 8 | budget | 3.68 | 3.58 | 230 † | 12.8 | 11.8 | 655 † |
| moto g05 | budget | 0.96 | 0.72 | 266 | 5.15 | 3.62 | 1,013 |
| Galaxy A35 | mid | 0.28 | 0.27 | 255 | 1.97 | 1.28 | 1,027 |
| Galaxy A55 | mid | 0.22 | 0.20 | 297 | 1.57 | 1.06 | 1,090 |
| Pixel 8a | mid | 0.36 | 0.54 | 279 | 1.96 | 1.74 | 1,030 |
| Pixel 9 Pro | flagship | 0.32 | 0.43 | 287 | 1.75 | 1.53 | 1,040 |
| Galaxy S23 Ultra | flagship | 0.21 | 0.18 | 263 | 1.06 | 0.76 | 1,547 |
| Pixel 11 Pro | flagship | 0.33 | 0.32 | 283 | 1.65 | 1.35 | 1,029 |
| Galaxy S26+ | flagship | 0.16 | 0.12 | 275 | 0.76 | 0.54 | 1,034 |

## Notes

- † The Infinix SMART 8's peaks are a floor: its warm iterations read far lower than its cold one
  (Prepare 115 to 251 MiB warm against 1,519 MiB cold). Its firmware also changed between the two
  dates (`analysis.md`, Warnings).
- Prepare ran on the Galaxy A06 but never finished. Each of its two attempts completed the cold
  iteration (10.9 and 11.4 s) and three or four warm ones, peaking at 2,045 and 2,064 MiB, before
  Android's low-memory killer stopped it. The iterations are in `openac.jsonl` and the kills in the
  trimmed logs; neither attempt left a proof. Presentations re-randomize a Prepare proof made on a
  laptop and pushed with the keys (`2k_prepare_instance.bin`, `2k_prepare_witness.bin`), so they
  ran on the A06 too.
- Like the browser SDK, Prepare here skips re-reading the 374 MB circuit description that the
  current mobile app reads on every Prepare. Presentations don't read it.
- The runs reused one set of shared blinds across presentations, where the SDK draws fresh ones each
  time. The work is the same, but the runs don't test that two presentations can't be linked.

## Files

`<phone>/<UTC start>/` is one session of the host runner on one phone:

- `session.json`: the phone's properties and memory, the APKs and pushed files with their sha256,
  and one entry per run attempt with its outcome, temperature, free memory and verification result.
- `<workload>.jsonl`: one record per line, `device`, `run`, `iter` (per iteration: `phase`,
  `load_ms`, `prove_ms`, `total_ms`, `peak_rss_kb`), `size` and `sample`.
- `raw/<run>-<attempt>.log`: the phone's logcat for that attempt, trimmed (below).
- `raw/<run>-<attempt>-out/`: the proofs pulled from the phone.

A run that didn't finish was retried once, and both attempts are kept. Where a phone has more than
one session for a workload, `analysis.md` uses the latest; its Devices table lists which.

The logs keep the logcat buffer headers, every marker line, every line from the app's processes,
and Android's process start, kill, death, crash and memory lines that name the app. Window,
package-manager and display services, which name the app thousands of times, are left out.
Normalizing these trimmed logs gives the same `.jsonl` records as the full logs. The full logs, the
host runner (`run_device.py`) and the predictions are kept with the article this benchmark was run
for, in a repository that is not yet public.

# Device results

## Warnings

- a55xzh-36: sessions report different MemTotal: 20261028T025220Z=7607776 kB, 20261030T030621Z=7607772 kB
- caiman-34: sessions report different MemTotal: 20261028T041033Z=15926120 kB, 20261030T032547Z=15926036 kB
- dm3q-34: sessions report different MemTotal: 20261028T034141Z=11294228 kB, 20261030T032531Z=11294224 kB
- infinix-x6525-33: sessions report different build fingerprints: 20261028T031715Z=Infinix/X6525-OP/Infinix-X6525:13/TP1A.220624.014/250313V1928:user/release-keys, 20261030T024144Z=Infinix/X6525-OP/Infinix-X6525:13/TP1A.220624.014/250513V1942:user/release-keys

## Feature × tier matrix

Each cell shows prediction → measurement. A miss is a different runs-or-not, or time or RAM off by more than 2x. † thermally gated or throttled runs are left out of the time and RAM columns. ‡ the run needed its retry.

| Row | Tier | Runs | Verified | Cold s | Warm median s (min–max) | Peak MiB | Verdict |
|---|---|---|---|---|---|---|---|
| OpenAC Prepare (once per credential) | budget | partial → partial (2/3) | 2/2 | 20.3 → 25.0 | 16.8 → 21.9 (10.2–33.8) | 2,133 → 1,832 | ok |
| OpenAC Prepare (once per credential) | mid | yes → yes (3/3) | 3/3 | 7.93 → 5.14 | 6.56 → 3.37 (2.87–4.48) | 2,133 → 1,941 | ok |
| OpenAC Prepare (once per credential) | flagship | yes → yes (4/4) | 4/4 | 5.58 → 3.45 | 4.62 → 2.65 (1.52–3.69) | 2,133 → 2,861 | ok |
| OpenAC presentation | budget | yes → yes (3/3) | 3/3 | 15.6 → 11.4 | 6.91 → 7.02 (5.83–12.1) | 1,484 → 1,975 | ok |
| OpenAC presentation | mid | yes → yes (3/3) | 3/3 | 6.12 → 4.11 | 2.71 → 2.52 (2.23–2.71) | 1,484 → 1,802 | ok |
| OpenAC presentation | flagship | yes → yes (4/4) | 4/4 | 4.31 → 2.99 | 1.91 → 1.70 (1.16–2.25) | 1,484 → 2,008 | ok |

### Step detail

| Row | Tier | Runs | Verified | Cold s | Warm median s (min–max) | Peak MiB | Verdict |
|---|---|---|---|---|---|---|---|
| OpenAC Show prove only | budget | yes (3/3) | 3/3 | 0.96 | 0.85 → 0.72 (0.47–3.71) | 275 | ok |
| OpenAC Show prove only | mid | yes (3/3) | 3/3 | 0.28 | 0.33 → 0.27 (0.19–0.59) | 297 | ok |
| OpenAC Show prove only | flagship | yes (4/4) | 4/4 | 0.26 | 0.23 → 0.25 (0.11–0.47) | 287 | ok |
| present: show_prove | budget | yes (3/3) | 3/3 | 0.69 | 0.69 (0.47–3.72) | 1,439 | no prediction |
| present: show_prove | mid | yes (3/3) | 3/3 | 0.27 | 0.26 (0.19–0.61) | 783 | no prediction |
| present: show_prove | flagship | yes (4/4) | 4/4 | 0.22 | 0.25 (0.11–0.44) | 1,762 | no prediction |
| present: prepare_reblind | budget | yes (3/3) | 3/3 | 6.03 | 5.88 → 5.91 (5.03–7.32) | 1,975 | ok |
| present: prepare_reblind | mid | yes (3/3) | 3/3 | 2.00 | 2.30 → 1.94 (1.77–2.29) | 1,802 | ok |
| present: prepare_reblind | flagship | yes (4/4) | 4/4 | 1.32 | 1.62 → 1.31 (0.98–1.67) | 2,008 | ok |
| present: show_reblind | budget | yes (3/3) | 3/3 | 0.30 | 0.31 (0.25–1.18) | 1,949 | no prediction |
| present: show_reblind | mid | yes (3/3) | 3/3 | 0.10 | 0.11 (0.08–0.19) | 778 | no prediction |
| present: show_reblind | flagship | yes (4/4) | 4/4 | 0.10 | 0.10 (0.04–0.17) | 2,008 | no prediction |

### Primitives

Single-primitive proofs outside the main matrix, with the same columns as the step detail.

| Row | Tier | Runs | Verified | Cold s | Warm median s (min–max) | Peak MiB | Verdict |
|---|---|---|---|---|---|---|---|
| Spartan2 SHA-256, 2 KB | budget | yes → yes (3/3) | 3/3 | 5.15 | 3.39 → 3.62 (2.50–11.8) | 792 → 1,359 | ok |
| Spartan2 SHA-256, 2 KB | mid | yes → yes (3/3) | 3/3 | 1.96 | 0.52 → 1.28 (1.05–1.79) | 792 → 1,090 | MISS: warm time |
| Spartan2 SHA-256, 2 KB | flagship | yes → yes (4/4) | 4/4 | 1.35 | 0.41 → 1.06 (0.52–1.60) | 792 → 1,547 | MISS: warm time |

## Devices

| Device | Tier | Model | SoC | RAM GiB | Android | MemAvailable before MiB | Thermal (start → max, gated, throttled) | Session | Flags |
|---|---|---|---|---|---|---|---|---|---|
| a06-35 | budget | SM-A065M | Mediatek MT6769V/CZ | 3.6 | 15 | 1,302–1,620 | 0 → 0, 0 gated, 0 throttled | 20261028T033036Z (openac), 20261030T021605Z (openac-primitives) | - |
| infinix-x6525-33 | budget | Infinix X6525 | Spreadtrum T606 | 3.7 | 13 | 2,328–2,534 | 0 → 0, 0 gated, 0 throttled | 20261028T031715Z (openac), 20261030T024144Z (openac-primitives) | - |
| lamul-35 | budget | moto g05 | Mediatek MT6769V/CB | 3.6 | 15 | 1,793–2,066 | 0 → 0, 0 gated, 0 throttled | 20261028T031552Z (openac), 20261030T025043Z (openac-primitives) | - |
| a35x-34 | mid | SM-A356U1 | Samsung s5e8835 | 5.3 | 14 | 2,720–2,816 | 0 → 0, 0 gated, 0 throttled | 20261028T033431Z (openac), 20261030T025919Z (openac-primitives) | - |
| a55xzh-36 | mid | SM-A5560 | Samsung s5e8845 | 7.3 | 16 | 4,152–4,184 | 0 → 0, 0 gated, 0 throttled | 20261028T025220Z (openac), 20261030T030621Z (openac-primitives) | - |
| akita-35 | mid | Pixel 8a | Google Tensor G3 | 7.4 | 15 | 3,423–3,577 | 0 → 0, 0 gated, 0 throttled | 20261028T033027Z (openac), 20261030T031305Z (openac-primitives) | - |
| caiman-34 | flagship | Pixel 9 Pro | Google Tensor G4 | 15.2 | 14 | 10,736–10,788 | 0 → 0, 0 gated, 0 throttled | 20261028T041033Z (openac), 20261030T032547Z (openac-primitives) | - |
| dm3q-34 | flagship | SM-S918B | QTI SM8550 | 10.8 | 14 | 6,993–7,086 | 0 → 0, 0 gated, 0 throttled | 20261028T034141Z (openac), 20261030T032531Z (openac-primitives) | - |
| grizzly-37 | flagship | Pixel 11 Pro | Google Tensor G6 | 11.4 | 17 | 6,596–6,866 | 0 → 0, 0 gated, 0 throttled | 20261028T040206Z (openac), 20261030T031832Z (openac-primitives) | - |
| m2q-36 | flagship | SM-S947U1 | QTI SM8850 | 10.9 | 16 | 6,098–6,659 | 0 → 0, 0 gated, 0 throttled | 20261028T035133Z (openac), 20261030T031204Z (openac-primitives) | - |

## Proof and artifact sizes

| Workload | Step | Proof | Artifacts on the phone |
|---|---|---|---|
| openac | prepare | 112.1 KB | prepare_proving 431.9 MB |
| openac | present | 159.5 KB | prepare_instance 68.0 KB, prepare_proving 431.9 MB, prepare_witness 67.2 MB, shared_blinds 40 B, show_proving 4.9 MB |
| openac | show | 47.4 KB | show_proving 4.9 MB |
| openac-primitives | sha256 | 85.8 KB | sha256_proving 216.4 MB |

## Phone-to-host time ratios

| Row | Host | Tier | Phone warm s (prove_ms) | Host warm s (prove_ms) | Warm ÷ warm | Phone cold s (total_ms) | Host cold s (total_ms, else wall†) | Cold ÷ cold |
|---|---|---|---|---|---|---|---|---|
| OpenAC Prepare (once per credential) | Apple M5 Max | budget | 21.9 | 1.35 | 16.2x | 25.0 | 1.63† | 15.3x |
| OpenAC Prepare (once per credential) | Apple M5 Max | mid | 3.37 | 1.35 | 2.5x | 5.14 | 1.63† | 3.2x |
| OpenAC Prepare (once per credential) | Apple M5 Max | flagship | 2.64 | 1.35 | 2.0x | 3.45 | 1.63† | 2.1x |
| OpenAC presentation | Apple M5 Max | budget | 7.00 | 0.50 | 13.9x | 11.4 | 1.14† | 10.1x |
| OpenAC presentation | Apple M5 Max | mid | 2.51 | 0.50 | 5.0x | 4.11 | 1.14† | 3.6x |
| OpenAC presentation | Apple M5 Max | flagship | 1.69 | 0.50 | 3.4x | 2.99 | 1.14† | 2.6x |
| OpenAC Show prove only | Apple M5 Max | budget | 0.71 | 0.05 | 14.6x | 0.96 | 0.07† | 12.8x |
| OpenAC Show prove only | Apple M5 Max | mid | 0.27 | 0.05 | 5.4x | 0.28 | 0.07† | 3.8x |
| OpenAC Show prove only | Apple M5 Max | flagship | 0.25 | 0.05 | 5.0x | 0.26 | 0.07† | 3.5x |
| present: show_prove | Apple M5 Max | budget | 0.69 | 0.05 | 13.9x | 0.69 | 0.07† | 9.2x |
| present: show_prove | Apple M5 Max | mid | 0.26 | 0.05 | 5.1x | 0.27 | 0.07† | 3.6x |
| present: show_prove | Apple M5 Max | flagship | 0.25 | 0.05 | 5.0x | 0.22 | 0.07† | 3.0x |
| present: prepare_reblind | Apple M5 Max | budget | 5.91 | 0.42 | 13.9x | 6.03 | 1.01† | 6.0x |
| present: prepare_reblind | Apple M5 Max | mid | 1.94 | 0.42 | 4.6x | 2.00 | 1.01† | 2.0x |
| present: prepare_reblind | Apple M5 Max | flagship | 1.31 | 0.42 | 3.1x | 1.32 | 1.01† | 1.3x |
| present: show_reblind | Apple M5 Max | budget | 0.31 | 0.03 | 11.8x | 0.30 | 0.05† | 5.6x |
| present: show_reblind | Apple M5 Max | mid | 0.11 | 0.03 | 4.2x | 0.10 | 0.05† | 1.8x |
| present: show_reblind | Apple M5 Max | flagship | 0.10 | 0.03 | 4.0x | 0.10 | 0.05† | 1.8x |
| Spartan2 SHA-256, 2 KB | Apple M5 Max | budget | 3.61 | 0.21 | 17.3x | 5.15 | 0.36† | 14.3x |
| Spartan2 SHA-256, 2 KB | Apple M5 Max | mid | 1.27 | 0.21 | 6.1x | 1.96 | 0.36† | 5.4x |
| Spartan2 SHA-256, 2 KB | Apple M5 Max | flagship | 1.06 | 0.21 | 5.1x | 1.35 | 0.36† | 3.7x |

† wall time of a fresh host process, used where the host has no `total_ms` for its cold run; it includes process start. ( ) numbers come from unverified runs and ⚑ from runs with errors.

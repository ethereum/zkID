# Row schema for openacplus-bench

Both producers write JSONL with one object per line:
- the Mac (`openac_bench` plus its driver, Track A)
- the phones (issue-40 flow harness, Tracks B and C)

The Track D analysis reads both with one parser.

The phone format is the source of truth. It is schema 2 as written by `bench/issue-40-arms`, with sample rows in `wallet-unit-poc/mobile/scripts/fixtures/emulator_bench.jsonl`. The Mac copies it and adds the fields marked (mac).

## Row kinds

`DEVICE`, written once per process:
- `platform` (`macos` | `android` | `ios`), `product_model`, `soc_model`, `cpu_count`, `mem_total_kb`, `rayon_default_threads`
- `run_id`, `bench_sha`, `base_sha`, `thermal_status`
- (mac): `config` (`main` | `issuer` | `revocation` | `combined`), `cell`, `jwt_size` (`1k` | `2k` | `4k` | `8k`), `d_iss`, `d_rev`, `issuers`, `revoked`, `iss_path_len`, `rev_path_len`, `visit`, `pass`, `r1cs_present`, `spartan2_rev`, `keys_sha256` (map of file to sha256), `r1cs_sha256`, `power` (`ac` | `battery`), `therm` (the `pmset -g therm` speed limit)
- Phones add `config` and `cell` through `bench_inputs.*.json` (the run_id prefix `openacplus/`).

`SIZES`: file name to bytes for the keys used.

`ITER`, one per measured step per iteration:
- `step` is one of:
  - `prepare_witness`, `prepare_prove`, `prepare_reblind`, `prepare_total`
  - `show_prove`, `show_reblind`, `present_total`
  - `verify`, `verify_total`, `vk_load`, `key_load_prepare`, `key_load_show`, `load_keys_total`
- `wall_us`, `phase` (`cold` | `warm`), `iter`, `threads`, `ok` (proof verified and linked)
- `flow`: `proof_bytes`, `instance_bytes`, `prove_ms`, `witness_ms`, `proof_fingerprint`
- Mac rows may omit the Android-only probes: `freq_khz`, `cpu0`, `cpu1`, `peak_kb` and `peak_is_step`.

`DONE`: end of process, with `errors`.

## Mac-only kinds

`CONSTRAINTS`, one per compiled circuit:
- `config`, `circuit` (`jwt_1k`.. | `show` | `ecdsa`), `d_iss`, `d_rev`, `jwt_size`
- `constraints`, `wires`, `public_inputs`, `private_inputs`, `outputs`, `labels`, `r1cs_sha256`

`PEAKMEM`, one per `/usr/bin/time -l` process:
- `config`, `cell`, `phase` (`prepare` | `present` | `verify` | `online`), `run`
- `max_rss_bytes`, `peak_footprint_bytes`, `wall_s`

`CONTROL`, before each visit:
- `power`, `low_power_mode`, `therm`, `load_avg_1m`, `idle_gate_pass`, `ts`

## Round 2 additions (2026-11-19)

Fields on `DEVICE`, also copied onto `SHAPE` rows and `E2E` rows:
- `config`: adds `v1` (v1.0.0) and `variant` (generic-path sweep cell). The others stay `main`, `issuer`, `revocation`, `combined`.
- `matrix_id`: `C0` | `A1` | `A2` | `S-N` | `S-D` | `S-P` | `S-MT` | `S-B` | `W` | `R1` | `E1` | `X1` | `X2` | `BR` | `PM`.
- `path`: `product` (the `flow.rs` calls on a ref) | `generic` (r1cs + wtns + layout file).
- `show_params`: the full Show template params as built, for example `[2,2,8,64,8,20]`. `null` for v1.0.0, whose Show is `Show(128)`.
- `jwt_params`: the JWT template params, for example `[2048,2000,4,50,128]`.
- `n_claims`, `m_pred`, `t_tok`, `beta`: unpacked from `show_params`.
- `population`: `{ "issuers": int, "revoked": int }`, the actual registry sizes behind the input.
- `workload`: `w1` | `w2` | `w3` | `eq` | `le` | `ge`, or `null`.
- `input_sha256`: the sha256 of the frozen input JSON or `.wtns`.
- `batch`: B, for S-B rows.

New row kinds:

`SHAPE`, one per compiled circuit (supersedes `CONSTRAINTS`; `CONSTRAINTS` rows are still read):
- `circuit`, `config`, the fields above
- `constraints`, `wires`, `public_inputs`, `private_inputs`, `outputs`, `labels`
- `nnz_a`, `nnz_b`, `nnz_c`
- `padded_constraints`, `padded_vars`, `num_shared`, `num_precommitted`, `num_rest`: Spartan `sizes()`, or `null` when there is no key
- `r1cs_sha256`

`REGISTRY`, one per timed registry operation (Node):
- `registry`: `issuer` | `revocation`
- `op`: `build` | `insert` | `remove` | `revoke` | `revoke_many` | `witness_member` | `witness_nonmember` | `root` | `refresh_incremental` | `refresh_rebuild` | `export` | `import`
- `population`, `k` (number of updates, for refresh), `wall_us`, `iter`, `phase`
- `bytes` (snapshot, index or delta size, where relevant), `heap_used_bytes`, `node_version`, `pkg_versions`

`E2E`, one per orchestrated end-to-end run:
- `workload`: `import` | `warm` | `cold` | `registry_update` | `stale_root_retry` | `refill`
- `stages`: list of `{ "name", "wall_us", "where": "mac" | "phone" | "node" }`
- `total_us`, `composed`: true when the stages were measured separately and summed

`CRASH`, one per failed visit attempt:
- `cell`, `attempt`, `signal` or `exit_code`, `stderr_tail`, `ts`

## Pinned 2026-11-19 (lead; producers and the analysis follow these)

1. **Provenance on every producer row.** Every `DEVICE`, `SHAPE`, `REGISTRY` and `E2E` row carries:
   - `command`: the exact command line that produced it
   - `commit`: the repo SHA of the tree that was built
   - `spartan2_rev`: the locked Spartan2 commit
   `E2E` rows also carry `platform` and `product_model`.
2. **Depths are explicit.** Producers write `d_iss` and `d_rev` on `DEVICE`, `SHAPE` and `E2E` rows, with 0 when the tree is absent. Deriving them from `show_params` is a fallback for legacy rows only. `show_params` order is `[N, M, T, beta, (D_iss), (D_rev)]`:
   - main: 4 params
   - issuer: 5, the 5th is D_iss
   - revocation: 5, the 5th is D_rev
   - combined: 6
3. **`SHAPE` counts.**
   - `constraints`, `wires`, `public_inputs`, `private_inputs`, `outputs`, `labels` are the r1cs header values.
   - `loaded_constraints` and `loaded_wires` come from `circom_scotia::load_r1cs`.
   - The analysis check is `constraints == loaded_constraints`. A row from Track B (header only) has no `loaded_*`, and the check skips it.
4. **Standalone SHA-256 gadget.** A `SHAPE` row with `circuit: "sha256"`, `matrix_id: "X2"`, and `compressions: 1`.
5. **New `ITER` step names:**
   - `statement_check`: public-value, root and policy acceptance, timed outside `verify`
   - `state_load`: loading the prepared state
   - `batch_reblind`: B reblinds of one prepared instance
   For `S-B`, `wall_us` of `batch_reblind` is the whole batch, and `DEVICE.batch` = B. Per tuple = `wall_us / B`. Bytes per tuple = `SIZES.batch_bytes / B`.
6. **Expected roots** for the statement check come from the registry: Track B's `*.roots.json` next to each input. They do not come from the circuit's own evaluation. Configs without registries (v1, main) take their expected nonce and policy from the frozen input.
7. **Hash count.** The measured number of SHA-256 compressions is `2·D_iss + 2 + 2·D_rev + 3`. The paper's prediction, read as 2 compressions per hash, is `2(D_iss + D_rev + 3)`. The one-compression gap is `sha256(secret)`, which fits in a single block. The analysis reports measured minus predicted, with that note.
8. **`E2E` stage names for the cold path:** `key_load`, `state_load` and `registry_load`, exactly. The other stages use the `ITER` step names (`prepare_prove`, `show_prove`, `present_total`, `verify_total`, `statement_check`, and so on), plus `witness_refresh` and `root_rejected` for the registry-update and stale-root workloads.
9. **`REGISTRY` additions.**
   - `op: "bandwidth"`, with a `method` field: `mirror` (changed leaf records plus root) or `proof_fetch` (a downloaded path). For these rows `bytes` is the per-update or per-proof size and `wall_us` is null.
   - The `E2E` stages `witness_inputs` and `witness_gen` are allowed and are summed into the workload total.

## Pinned after review round 1 (2026-11-19). These override the earlier pins wherever they conflict.

10. **One name per config.** The (8,20) headline is `config: "combined"` with `d_iss: 8, d_rev: 20`; "headline" appears only in cell ids. `config` takes exactly one of `v1|main|issuer|revocation|combined|variant`. Mobile DEVICE rows must carry `config`; the analysis fails a mobile row without it and never defaults it.
11. **Verify definition, on every platform.**
    - `verify` is proof verification plus linkage only, with the VKs already in memory. It is the cross-platform comparable step.
    - `vk_load` reads VKs from storage. The row carries `vk_loaded` (for example `["prepare","show"]`). Platforms are compared on `vk_load` only for the first or cold iteration with both VKs loaded.
    - `vk_digest` is the Mac-only step that forces the VK digest. Spartan2 d687dbb computes it. The phones restore it from the PR #115 sidecar inside `vk_load`, and their DEVICE row says `vk_digest: "sidecar"`.
    - `statement_check` is separate.
    - "Verify + acceptance" = `verify` + `statement_check`, summed per iteration.
    - `verify_total` is kept for compatibility, but no table uses it.
12. **Show timing on the product and generic paths.**
    - Product path:
      - `show_witness` is the Show witness generation.
      - `show_prove_only` is the prove without the witness.
      - `show_prove` = `show_witness` + `show_prove_only`, which matches the phone's `show_prove`.
    - Generic path (precomputed `.wtns`):
      - `show_prove` is the prove only. It is comparable to product `show_prove_only`, not to product `show_prove`.
      - The totals are `show_total` or `prepare_total`. The generic path never emits `present_total`.
    - Every row has `path`. A sweep series never mixes paths.
13. **`ok` on every ITER row, on every platform.**
    - A verify row's `ok` is the verify verdict.
    - present, prepare and statement rows take `ok` from the verdict of the proof they produced, checked outside the timer.
    - An `ERROR` row with `(step, iter)` rejects that iteration.
    - `DONE.errors > 0` fails the cell.
14. **Smoke separation.**
    - Smoke rows carry `smoke: true` and live under a `smoke/` path segment (`laptop/smoke/`, `mobile/smoke/`, `e2e/*smoke*`, `registry/*smoke*`).
    - The analysis ignores any path with a `smoke` segment unless `--include-smoke` is passed.
15. **Mac loads.**
    - Mac DEVICE rows carry `page_cache: "warm"`.
    - Mac key, state and VK loads have `phase: "first"`, not `cold`.
    - Phones keep `cold`, because they bypass the cache.
16. **Thermal state.**
    - Mac CONTROL and DEVICE rows carry `thermal_pressure`, from `com.apple.system.thermalpressurelevel` (0 = nominal).
    - Phone ITER rows carry `thermal_status` and `thermal_status_before`.
17. **Provenance.**
    - Generic cells carry `circuit_commit`, the commit the r1cs, wtns and keys came from, alongside the harness `commit`.
    - INPUT and SHAPE rows carry `commit`, the source tree of the circuits. `main`-circuit rows say `9557067`.
    - `spartan2_rev` is the locked rev, or `"n/a:<reason>"`.
    - PEAKMEM rows carry `commit`, `binary_sha256`, `command`, `config`, `d_iss`, `d_rev` and `threads`.
    - A cell whose rows mix `commit`, `r1cs_sha256` or `keys_sha256` fails a check.
18. **Chain cells** (issuer, revocation, combined (8,10)) carry their actual `population` and `roots_source: "circuit"`. Cells staged against a registry roots file say `roots_source: "registry"`.
19. **`E2E` workloads.**
    - A total sums only non-overlapping stages. `present_total` already includes `show_prove`, and `vk_load` is reported apart, not inside any total.
    - `registry_update` is "wallet witness refresh, then a presentation". The authority's `revokeMany` is a separate `REGISTRY` op, not a stage of it.
    - `witness_refresh` means the same thing in `E2E` and `REGISTRY`: apply k updates to the mirror, then regenerate the proof. Run it in a GC-quiesced process (`--expose-gc`, `gc()` before each timed region).
20. **`REGISTRY` op names.**
    - `path_verify` replaces the old `root`, which timed a wallet-side path re-hash.
    - `root_recompute` is a full root recomputation, if measured.
    - Bandwidth `method` is `mirror_upper` (changed records, the old `mirror`), `mirror_min` (k·32 + 32 B) or `proof_fetch`.
    - `bytes` is the total for that k; `bytes_per_update` = `bytes / k`.
    - Proof-fetch bytes are computed at the labelled population and depth.
21. **`PHONECHECK` rows** (written by the lead after `verify_device_proofs.sh` and the root comparison): `device`, `config`, `session`, `proofs_valid`, `linked`, `roots_match_registry`, `command`. The `--final` gate requires one per phone session.
22. **Fixture tags** (`bench_host` and phone rows): `fixture` holds the fixture name (for example `over18`), and `fixture_expect` is `"accept"` or `"reject"`. Measured BR and phone cells use only `fixture_expect: "accept"`. The analysis excludes and reports any row whose `fixture_expect` is `"reject"`. A row without `fixture_expect` counts as accept only when `fixture` is absent.
23. **Expected phone sessions:** `mobile/expected_sessions.json`, written by the lead, maps `{device: {config: n}}`, for example `{"iphone17pro-26-5": {"main": 3, "combined": 3}, "m2q-36": {...}}`. Under `--final`, every device/config pair must have n measured (non-smoke) sessions.

`SIZES` additions:
- `prepared_state_bytes`, split into `instance`, `witness` and `blinds`
- `presentation_bytes`: everything the verifier receives, meaning both proofs, the commitments and the public values
- `footprint_bytes`: what the wallet stores per credential (keys, witness-gen artifacts, prepared state)

## Files

| Path under `$OPENACPLUS_BENCH_ROOT/` | Contents |
|---|---|
| `laptop/runs/<run_id>/bench.jsonl` | `DEVICE`/`SIZES`/`ITER`/`DONE`/`CONTROL` |
| `laptop/constraints.jsonl` | `CONSTRAINTS` |
| `laptop/peakmem.jsonl` | `PEAKMEM` |
| `mobile/<phase>/openacplus/<run_id>/<device>/**/bench.jsonl` | phone rows, as pulled by `ddp_run.py` (the actual layout). The analysis finds `mobile/**/bench.jsonl` recursively and routes by the `DEVICE` row's `config`, `cell` and `product_model`, not by path. |

## Registry rows (phase 2)

The second registry run (`registry-bench.ts`) adds fields and ops, and changes what a few ops time. Readers ignore fields they do not know, and the analysis does the same.

New fields:
- `calls`: 1, or 1000 for micro-ops. `wall_us` is per call and a float.
- `ok`: true on rows whose result was verified.
- `entries_before`, `entries_after`: on mutating ops.
- `depth_after`: on issuer mutating ops.
- `beyond_circuit`: on issuer rows; true when the population is over 256, the most the built circuit holds.

New ops:
- `lookup`, with `method` `hit` or `miss`.
- `to_commitment`; issuer rows carry `method: "in_generate_proof"`.
- `leaf_slots` (revocation).
- `sync`, `unrevoke`, `update`.
- `insert_many`, with k = 1 or 100.
- `revoke_many`, with k = 1, 100 or 1000.
- `bandwidth` with `method: "full_sync"`; `wall_us` and `k` are null.

Changed semantics:
- `insert` takes a registry from population − 1 to population.
- `remove` removes from a fresh full tree.
- Witnesses and `path_verify` time 1000 calls per region.
- Mutating ops start each iteration from a fresh `import(snapshot, false)`.

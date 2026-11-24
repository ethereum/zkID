import assert from "assert";
import { acceptPresentation, assertOnlyRegistryFieldsChanged, composeRow, presentStages, stalePair, type Stage } from "../../scripts/benchmarks/e2e-registry.ts";

describe("e2e registry helpers", () => {
  it("accepts only a presentation whose roots equal the verifier's accepted roots", () => {
    const accepted = { issuerRoot: 5n, revocationRoot: 9n };
    assert.deepStrictEqual(acceptPresentation({ issuerRoot: 5n, revocationRoot: 9n }, accepted), { ok: true });
    assert.deepStrictEqual(acceptPresentation({ issuerRoot: 5n, revocationRoot: 8n }, accepted), { ok: false, reason: "revocationRoot" });
    assert.deepStrictEqual(acceptPresentation({ issuerRoot: 4n, revocationRoot: 9n }, accepted), { ok: false, reason: "issuerRoot" });
  });

  it("sums stage times into a composed row", () => {
    const stages: Stage[] = [
      { name: "a", wall_us: 10, where: "node" },
      { name: "b", wall_us: 32, where: "mac" },
    ];
    const row = composeRow("stale_root_retry", stages, true);
    assert.strictEqual(row.total_us, 42);
    assert.strictEqual(row.kind, "E2E");
    assert.strictEqual(row.composed, true);
  });

  it("allows only registry witness fields to differ from the staged input", () => {
    const staged = { nonce: "1", revocationDepth: "20", revocationSiblings: [["1", "2"]] };
    assertOnlyRegistryFieldsChanged(staged, { ...staged, revocationDepth: "21", revocationSiblings: [["3", "4"]] });
    assert.throws(() => assertOnlyRegistryFieldsChanged(staged, { ...staged, nonce: "2" }), /nonce/);
  });

  const res = (extra = {}) => ({ ok: true, statement_ok: true, present_total_ms: 1500, show_prove_ms: 700, verify_total_ms: 3200, statement_check_ms: 0.02, ...extra });

  it("keeps show_prove and vk_load out of the stages", () => {
    const p = presentStages(res({ verify_ms: 180, vk_load_ms: 3000, vk_digest_ms: 12 }), 1, "statement_check", 300);
    assert.deepStrictEqual(p.stages.map((s) => s.name), ["witness_inputs", "present_total", "verify", "statement_check"]);
    assert.strictEqual(p.detail.show_prove_ms, 700);
    assert.strictEqual(p.detail.vk_load_ms, 3000);
    assert.strictEqual(p.vkInVerify, false);
  });

  it("falls back to verify_total and flags the VK load inside it", () => {
    const p = presentStages(res(), 1, "statement_check", 300);
    assert.ok(p.stages.some((s) => s.name === "verify_total"));
    assert.strictEqual(p.vkInVerify, true);
  });

  it("builds stale_root_retry from both presentations and registry_update from the second only", () => {
    const first = presentStages(res({ verify_ms: 180 }), 1, "root_rejected", 300);
    const second = presentStages(res({ verify_ms: 180 }), 2, "statement_check", 300);
    const refresh: Stage = { name: "witness_refresh", wall_us: 25_000, where: "node" };
    const [update, stale] = stalePair(first, refresh, second, {});
    const sum = (xs: Stage[]) => xs.reduce((a, s) => a + s.wall_us, 0);
    assert.strictEqual(stale.workload, "stale_root_retry");
    assert.strictEqual(update.workload, "registry_update");
    assert.strictEqual(update.total_us, sum([refresh, ...second.stages]));
    assert.strictEqual(stale.total_us, sum([...first.stages, refresh, ...second.stages]));
    assert.ok(!update.stages.some((s) => s.name === "registry_update"));
    const keys = stale.stages.map((s) => `${s.name}#${s.attempt}`);
    assert.strictEqual(new Set(keys).size, keys.length);
  });
});

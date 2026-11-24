import assert from "assert";
import { jobs } from "../../scripts/benchmarks/build-inputs.ts";

describe("build-inputs jobs", () => {
  const sd = jobs("timed").filter((j) => j.matrix === "S-D");

  it("gives every S-D input one population that fits depth 8", () => {
    assert.ok(sd.length >= 9);
    for (const j of sd) {
      assert.strictEqual(j.issuers, 256);
      assert.strictEqual(j.revoked, 128);
    }
  });

  it("includes the (8,20) reference circuit in the S-D series", () => {
    assert.ok(sd.some((j) => j.cell === "sn_show_n2"));
  });

  it("keeps S-P populations separate", () => {
    const sp = jobs("population").map((j) => j.revoked);
    assert.deepStrictEqual(sp.sort((a, b) => a - b), [1024, 32768]);
  });
});

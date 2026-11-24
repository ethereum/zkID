import assert from "assert";
import { allCells, mainSource } from "../../scripts/benchmarks/variants.ts";

describe("sweep variants", () => {
  const cells = allCells();

  it("has unique names", () => {
    assert.strictEqual(new Set(cells.map((c) => c.name)).size, cells.length);
  });

  it("covers the matrix", () => {
    const count = (m: string) => cells.filter((c) => c.matrix === m).length;
    assert.strictEqual(count("X2"), 81);
    assert.strictEqual(count("S-D"), 8);
    assert.strictEqual(count("S-MT"), 8);
    assert.strictEqual(count("S-N"), 10);
    assert.strictEqual(count("S-B"), 3);
  });

  it("pairs JWT maxMatches with Show nClaims at N + 2", () => {
    for (const c of cells.filter((x) => x.matrix === "S-N" && x.kind === "jwt")) {
      const showN = Number(c.name.match(/_n(\d+)$/)![1]);
      assert.strictEqual(c.params[2], showN + 2);
    }
  });

  it("emits a main file naming the template and params", () => {
    const c = cells.find((x) => x.name === "sd_d8_r8")!;
    assert.match(mainSource(c), /Show\(2, 2, 8, 64, 8, 8\)/);
    assert.match(mainSource(c), /include "show\.circom"/);
  });
});

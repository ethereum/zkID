import assert from "assert";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { assertSingleSetting, benchRoot, e2eFileName, requireGc, stampCommit } from "../../scripts/benchmarks/provenance.ts";

describe("provenance helpers", () => {
  it("marks a dirty tree", () => {
    assert.strictEqual(stampCommit("abc", false), "abc");
    assert.strictEqual(stampCommit("abc", true), "abc-dirty");
  });

  it("refuses a measured run without gc and allows smoke", () => {
    assert.throws(() => requireGc(false, undefined), /expose-gc/);
    assert.doesNotThrow(() => requireGc(true, undefined));
    assert.doesNotThrow(() => requireGc(false, () => {}));
  });

  it("names an E2E file by k and population", () => {
    assert.strictEqual(e2eFileName(100, 1046528), "e2e-k100-r1046528.jsonl");
  });

  it("rejects mixing k or population in one output file", () => {
    const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "prov-")), "x.jsonl");
    fs.writeFileSync(f, JSON.stringify({ k: 100, revoked: 1024 }) + "\n");
    assert.doesNotThrow(() => assertSingleSetting(f, 100, 1024));
    assert.throws(() => assertSingleSetting(f, 10, 1024), /one k and one population/);
    assert.throws(() => assertSingleSetting(f, 100, 2048), /one k and one population/);
    fs.rmSync(path.dirname(f), { recursive: true, force: true });
  });

  describe("benchRoot", () => {
    it("fails with a clear message when OPENACPLUS_BENCH_ROOT is unset or empty", () => {
      assert.throws(() => benchRoot({}), /OPENACPLUS_BENCH_ROOT/);
      assert.throws(() => benchRoot({ OPENACPLUS_BENCH_ROOT: "" }), /OPENACPLUS_BENCH_ROOT/);
    });

    it("refuses a root inside a git work tree, existing or not", () => {
      assert.throws(() => benchRoot({ OPENACPLUS_BENCH_ROOT: __dirname }), /git work tree/);
      assert.throws(() => benchRoot({ OPENACPLUS_BENCH_ROOT: path.join(__dirname, "not", "yet") }), /git work tree/);
    });

    it("accepts a directory outside any work tree, created or not", () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bench-root-"));
      assert.strictEqual(benchRoot({ OPENACPLUS_BENCH_ROOT: dir }), fs.realpathSync(dir));
      assert.strictEqual(benchRoot({ OPENACPLUS_BENCH_ROOT: path.join(dir, "sub") }), path.join(fs.realpathSync(dir), "sub"));
      fs.rmSync(dir, { recursive: true, force: true });
    });
  });
});

import { describe, it, expect } from "vitest";
import { WasmBridge, ABI_VERSION } from "../src/wasm-bridge.js";
import { OpenACError } from "../src/errors.js";

const ok = {
  valid: true,
  prepare_public_values: [],
  show_public_values: [],
  error: null,
};

function fakeModule(overrides: Record<string, unknown> = {}) {
  return {
    init() {},
    abi_version: () => ABI_VERSION,
    verify: () => ok,
    ...overrides,
  };
}

const args = [new Uint8Array(), new Uint8Array(), new Uint8Array(), new Uint8Array(), new Uint8Array(), new Uint8Array()] as const;

describe("WASM ABI version", () => {
  it("control: a matching abi_version initializes", () => {
    const b = new WasmBridge();
    b.initWithModule(fakeModule());
    expect(b.isInitialized).toBe(true);
  });

  it("fails closed when abi_version is missing", () => {
    const b = new WasmBridge();
    expect(() => b.initWithModule(fakeModule({ abi_version: undefined }))).toThrow(/abi_version/);
    expect(b.isInitialized).toBe(false);
  });

  it("fails closed when abi_version differs", () => {
    const b = new WasmBridge();
    expect(() => b.initWithModule(fakeModule({ abi_version: () => ABI_VERSION + 1 }))).toThrow(
      /ABI version/,
    );
    expect(b.isInitialized).toBe(false);
  });
});

describe("a WASM trap poisons the bridge", () => {
  it("control: a normal call returns", async () => {
    const b = new WasmBridge();
    b.initWithModule(fakeModule());
    expect((await b.verify(...args)).valid).toBe(true);
  });

  it("after a RuntimeError every later call fails with WASM_POISONED", async () => {
    let calls = 0;
    const b = new WasmBridge();
    b.initWithModule(
      fakeModule({
        verify: () => {
          calls++;
          throw new WebAssembly.RuntimeError("unreachable");
        },
      }),
    );
    const first = await b.verify(...args);
    expect(first.valid).toBe(false);

    const err = await b.verify(...args).then(
      () => null,
      (e) => e,
    );
    expect(err).toBeInstanceOf(OpenACError);
    expect(err.code).toBe("WASM_POISONED");
    await expect(b.precomputeShowFromWitness(args[0], args[1])).rejects.toMatchObject({
      code: "WASM_POISONED",
    });
    expect(calls).toBe(1);
  });

  it("an ordinary Error (not a trap) does not poison", async () => {
    let n = 0;
    const b = new WasmBridge();
    b.initWithModule(
      fakeModule({
        verify: () => {
          if (n++ === 0) throw new Error("bad proof bytes");
          return ok;
        },
      }),
    );
    expect((await b.verify(...args)).valid).toBe(false);
    expect((await b.verify(...args)).valid).toBe(true);
  });
});

describe("WASM_POISONED is realm-wide", () => {
  // The wasm-bindgen glue caches one instance per realm, so a second bridge
  // over the same module object would reuse the trapped instance and memory.
  it("a second bridge over the trapped module fails without calling into it", async () => {
    let abiCalls = 0;
    let verifyCalls = 0;
    const mod = fakeModule({
      abi_version: () => {
        abiCalls++;
        return ABI_VERSION;
      },
      verify: () => {
        verifyCalls++;
        throw new WebAssembly.RuntimeError("unreachable");
      },
    });
    const first = new WasmBridge();
    first.initWithModule(mod);
    await first.verify(...args);
    const abiBefore = abiCalls;

    const second = new WasmBridge();
    expect(() => second.initWithModule(mod)).toThrow(/WASM_POISONED|trapped/);
    try {
      second.initWithModule(mod);
    } catch (e) {
      expect((e as { code?: string }).code).toBe("WASM_POISONED");
    }
    expect(second.isInitialized).toBe(false);
    expect(abiCalls).toBe(abiBefore);
    expect(verifyCalls).toBe(1);
  });

  it("control: a different module is unaffected", () => {
    const b = new WasmBridge();
    b.initWithModule(fakeModule());
    expect(b.isInitialized).toBe(true);
  });
});

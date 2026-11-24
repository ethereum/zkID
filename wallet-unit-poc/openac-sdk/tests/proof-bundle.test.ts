import { describe, it, expect } from "vitest";
import { deserializeProofBundle, serializeProofBundle } from "../src/prover.js";

const bundle = () => ({
  prepareProof: new Uint8Array([1, 2, 3]),
  showProof: new Uint8Array([4, 5]),
  prepareInstance: new Uint8Array([6]),
  showInstance: new Uint8Array([7, 8, 9, 10]),
});

const frame = (bytes: Uint8Array) => {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length, true);
  out.set(bytes, 4);
  return out;
};
const concat = (...a: Uint8Array[]) => {
  const out = new Uint8Array(a.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of a) {
    out.set(x, o);
    o += x.length;
  }
  return out;
};

describe("1789508531: proof bundle framing is canonical", () => {
  it("control: serialize/deserialize round-trips", () => {
    const b = bundle();
    const out = deserializeProofBundle(serializeProofBundle(b));
    expect(out.prepareProof).toEqual(b.prepareProof);
    expect(out.showProof).toEqual(b.showProof);
    expect(out.prepareInstance).toEqual(b.prepareInstance);
    expect(out.showInstance).toEqual(b.showInstance);
  });

  it("rejects a short final frame", () => {
    const wire = serializeProofBundle(bundle());
    expect(() => deserializeProofBundle(wire.slice(0, wire.length - 1))).toThrow(/frame/i);
  });

  it("rejects a final frame whose declared length overruns the buffer", () => {
    const wire = serializeProofBundle(bundle()).slice();
    // The last frame is 4 bytes of payload behind a 4-byte length.
    new DataView(wire.buffer).setUint32(wire.length - 8, 1000, true);
    expect(() => deserializeProofBundle(wire)).toThrow(/frame/i);
  });

  it("rejects trailing bytes", () => {
    const wire = serializeProofBundle(bundle());
    expect(() => deserializeProofBundle(concat(wire, new Uint8Array([0])))).toThrow(/trailing/i);
  });

  it("rejects a truncated length prefix", () => {
    const b = bundle();
    // Four complete frames, then 2 bytes where the fifth frame's 4-byte length belongs.
    const wire = concat(
      frame(new TextEncoder().encode("0.2.0")),
      frame(b.prepareProof),
      frame(b.showProof),
      frame(b.prepareInstance),
      new Uint8Array([1, 0]),
    );
    expect(() => deserializeProofBundle(wire)).toThrow(/missing frame length/i);
  });

  it("rejects an unknown version", () => {
    const b = bundle();
    const wire = concat(
      frame(new TextEncoder().encode("0.1.0")),
      frame(b.prepareProof),
      frame(b.showProof),
      frame(b.prepareInstance),
      frame(b.showInstance),
    );
    expect(() => deserializeProofBundle(wire)).toThrow(/version/i);
  });
});

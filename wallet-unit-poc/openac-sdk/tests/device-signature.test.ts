import { describe, it, expect } from "vitest";
import { p256 } from "@noble/curves/p256";
import { invert } from "@noble/curves/abstract/modular";

import { signDeviceNonce, buildShowCircuitInputs } from "../src/inputs/show-input-builder.js";
import { DEFAULT_SHOW_PARAMS } from "../src/types.js";
import { bigintToBase64url } from "../src/utils.js";

const N = p256.CURVE.n;
const PRIV = "0x" + "11".repeat(32);
const pub = p256.ProjectivePoint.BASE.multiply(BigInt(PRIV));
const deviceKey = {
  kty: "EC" as const,
  crv: "P-256" as const,
  x: bigintToBase64url(pub.x),
  y: bigintToBase64url(pub.y),
};

const b64u = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const sigS = (sig: string) => BigInt("0x" + Buffer.from(sig, "base64url").subarray(32).toString("hex"));

describe("low-S device signatures", () => {
  it("signDeviceNonce never emits a high-S signature", () => {
    for (let i = 0; i < 200; i++) {
      const s = sigS(signDeviceNonce(`device-nonce-${i}-abcdef`, PRIV));
      expect(s <= N >> 1n).toBe(true);
    }
  });

  it("buildShowCircuitInputs normalizes a high-S signature to the low-S form", () => {
    const nonce = "high-s-nonce-0123456789";
    const lowBytes = Buffer.from(signDeviceNonce(nonce, PRIV), "base64url");
    const r = BigInt("0x" + lowBytes.subarray(0, 32).toString("hex"));
    const sLow = BigInt("0x" + lowBytes.subarray(32).toString("hex"));
    expect(sLow <= N >> 1n).toBe(true);

    // The same signature with s' = n - s: valid ECDSA, but high-S.
    const sHigh = N - sLow;
    expect(sHigh > N >> 1n).toBe(true);
    const highBytes = Buffer.from(lowBytes);
    highBytes.set(Buffer.from(sHigh.toString(16).padStart(64, "0"), "hex"), 32);

    const inputs = buildShowCircuitInputs(
      DEFAULT_SHOW_PARAMS,
      nonce,
      b64u(highBytes),
      deviceKey,
    );
    expect(inputs.sig_r).toBe(r);
    // The circuit gets the inverse of the low-S value, computed independently.
    expect(inputs.sig_s_inverse).toBe(invert(sLow, N));
  });

  it("control: a low-S signature passes through unchanged", () => {
    const sig = signDeviceNonce("control-nonce-0123456789", PRIV);
    const inputs = buildShowCircuitInputs(DEFAULT_SHOW_PARAMS, "control-nonce-0123456789", sig, deviceKey);
    expect(inputs.sig_r).toBe(BigInt("0x" + Buffer.from(sig, "base64url").subarray(0, 32).toString("hex")));
  });
});

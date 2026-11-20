import { strict as assert } from "assert";
import type { WitnessTester } from "circomkit";
import { p256 } from "@noble/curves/nist.js";
import { circomkit } from "../common/index.ts";
import { generateMockData } from "../../src/mock-vc-generator.ts";
import { base64urlToBigInt, bigintToBase64url } from "../../src/utils.ts";
import { witnessIndices } from "../common/witness-signals.ts";

// Swarm finding 1789506251: alternate signed device-key anchor.
//
// Match slots 0/1 are pinned to the literal '"x":"' / '"y":"', but the prover
// picks which occurrence matchIndex[0]/[1] points at. If the issuer signs a
// payload carrying a second P-256 JWK, the holder can bind the presentation to
// that key instead of cnf.jwk. The fix requires each anchor to occur exactly
// once in the signed payload, so there is no occurrence left to choose.

const CIRCUIT_PARAMS = [2048, 2000, 4, 50, 128];

function attackerJwk() {
  const point = p256.ProjectivePoint.fromPrivateKey(p256.utils.randomPrivateKey());
  return { kty: "EC", crv: "P-256", x: bigintToBase64url(point.x), y: bigintToBase64url(point.y) };
}

async function keyBinding(circuit: WitnessTester<any, any>, w: bigint[]) {
  const [x, y] = await witnessIndices(circuit, ["main.KeyBindingX", "main.KeyBindingY"]);
  return { x: w[x], y: w[y] };
}

describe("CountPatternOccurrences", () => {
  let circuit!: WitnessTester<["in"], ["count"]>;

  before(async () => {
    circuit = await circomkit.WitnessTester("CountPatternOccurrences", {
      file: "jwt_tx_builder/bytes",
      template: "CountPatternOccurrences",
      params: [8, 3, "[1, 2, 3]"],
    });
  });

  it("counts matches, including the first and last window", async () => {
    await circuit.expectPass({ in: [1, 2, 3, 0, 0, 1, 2, 3] }, { count: 2 });
  });

  it("returns 0 for near misses", async () => {
    await circuit.expectPass({ in: [1, 2, 4, 3, 2, 1, 1, 2] }, { count: 0 });
  });

  it("counts overlapping matches", async () => {
    const overlap = await circomkit.WitnessTester("CountPatternOverlap", {
      file: "jwt_tx_builder/bytes",
      template: "CountPatternOccurrences",
      params: [5, 3, "[7, 0, 7]"],
    });
    await overlap.expectPass({ in: [7, 0, 7, 0, 7] }, { count: 2 });
  });
});

describe("JWT device-key anchor uniqueness (1789506251)", () => {
  let circuit!: WitnessTester<any, any>;

  before(async () => {
    circuit = await circomkit.WitnessTester("JWTDeviceKeyAnchor", {
      file: "jwt",
      template: "JWT",
      params: CIRCUIT_PARAMS,
      recompile: true,
    });
    console.log("#constraints:", await circuit.getConstraintCount());
  });

  it("binds an ordinary credential to cnf.jwk", async () => {
    const mock = await generateMockData({ circuitParams: CIRCUIT_PARAMS });
    const w = await circuit.calculateWitness(mock.circuitInputs);
    await circuit.expectConstraintPass(w);
    const key = await keyBinding(circuit, w);
    assert.equal(key.x, base64urlToBigInt(mock.deviceKey.x));
    assert.equal(key.y, base64urlToBigInt(mock.deviceKey.y));
  });

  it("rejects a witness that points the anchors at a second signed JWK", async () => {
    const atk = attackerJwk();
    const mock = await generateMockData({
      circuitParams: CIRCUIT_PARAMS,
      extraPayload: { backup: { jwk: atk } },
    });
    const payload = atob(mock.token.split(".")[1]);
    const honest = mock.circuitInputs;
    const altX = payload.indexOf('"x":"', honest.matchIndex[0] + 1);
    const altY = payload.indexOf('"y":"', honest.matchIndex[1] + 1);
    assert.ok(altX > honest.matchIndex[0] && altY > honest.matchIndex[1], "second JWK must be signed");

    // Same signed message, signature and claims; only slots 0/1 move.
    const attack = { ...honest, matchIndex: [altX, altY, ...honest.matchIndex.slice(2)] };

    let w: bigint[] | null = null;
    try {
      w = await circuit.calculateWitness(attack);
    } catch {}
    if (w !== null) {
      const key = await keyBinding(circuit, w);
      const stolen = key.x === base64urlToBigInt(atk.x) && key.y === base64urlToBigInt(atk.y);
      assert.fail(`attack witness accepted; KeyBinding ${stolen ? "is the attacker's key" : "is not cnf.jwk"}`);
    }
  });

  it("rejects even the honest witness when the payload carries a second JWK", async () => {
    const mock = await generateMockData({
      circuitParams: CIRCUIT_PARAMS,
      extraPayload: { backup: { jwk: attackerJwk() } },
    });
    await assert.rejects(() => circuit.calculateWitness(mock.circuitInputs), /Assert Failed/);
  });
});

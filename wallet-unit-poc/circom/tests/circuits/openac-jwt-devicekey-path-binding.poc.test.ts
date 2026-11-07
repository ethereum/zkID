import { strict as assert } from "assert";
import type { WitnessTester } from "circomkit";
import { p256 } from "@noble/curves/nist.js";
import { circomkit } from "../common/index.ts";
import { generateMockData } from "../../src/mock-vc-generator.ts";
import { base64urlToBigInt, bigintToBase64url, stringToPaddedBigIntArray } from "../../src/utils.ts";
import { witnessValues } from "../common/witness-signals.ts";

// PoC (FIXED: jwt.circom now pins match slots 0/1 to the '"x":"' / '"y":"'
// literals, so the re-aiming below is rejected; the test asserts the fix).
//
// Original finding: jwt.circom:124-125 derived the device-binding key location from the
// unconstrained prover inputs matchIndex[0..1] / matchLength[0..1]. Nothing ties
// matchSubstring[0]/[1] to the literals '"x":"' / '"y":"' (that is only an SDK
// convention, openac-sdk/src/inputs/jwt-input-builder.ts:171), so the prover can
// aim the extractor at ANY 43-char base64url run inside the signed payload.
//
// Length-1 substring trick (keyless_zk_proofs/arrays.circom:180):
//   substr = [payload[K], 0, 0, ...], substr_len = 1
//   => substr_poly_eval = payload[K], str_poly_eval = payload[K] * c^K
//   => str_poly_eval === c^K * substr_poly_eval is an identity, satisfied for
//      every K with payload[K] != 0. Hence xStartIndex = K + 1 is free.

const CIRCUIT_PARAMS = [2048, 2000, 4, 50, 128];
const MAX_SUBSTRING_LENGTH = CIRCUIT_PARAMS[3];
const MAX_PAYLOAD_LENGTH = (CIRCUIT_PARAMS[1] * 3) / 4;

function attackerKey() {
  const priv = p256.utils.randomPrivateKey();
  const point = p256.ProjectivePoint.fromPrivateKey(priv);
  return { priv, x: bigintToBase64url(point.x), y: bigintToBase64url(point.y) };
}

/** Repoint match slot `slot` at payload offset `target` via the length-1 trick. */
function aimSlot(inputs: any, slot: number, payload: string, target: number) {
  const k = target - 1;
  assert.ok(k >= 0 && k < MAX_PAYLOAD_LENGTH, `K=${k} out of range`);
  const c = payload.charCodeAt(k);
  assert.ok(c !== 0 && !Number.isNaN(c), `payload[${k}] must be non-zero (arrays.circom:222)`);
  inputs.matchIndex[slot] = k;
  inputs.matchLength[slot] = 1;
  inputs.matchSubstring[slot] = stringToPaddedBigIntArray(payload[k], MAX_SUBSTRING_LENGTH);
}

// As of the "keep claim values and device key out of Prepare public IO" fix,
// JWT has NO public outputs: normalizedClaimValues and KeyBindingX/Y are private
// signals reaching Show through comm_W_shared. Their witness positions are
// compiler-assigned, so they are looked up from the .sym rather than read at a
// fixed offset. (Being private does not stop this PoC: Show consumes exactly
// these signals, so a forged device key here is a forged key downstream.)
const MAX_CLAIMS = CIRCUIT_PARAMS[2] - 2;
const CIRCUIT_NAME = "JWTKeyPathPoC";

async function outputs(circuit: WitnessTester<any, any>, w: bigint[]) {
  const names = [
    "main.KeyBindingX",
    "main.KeyBindingY",
    ...Array.from({ length: MAX_CLAIMS }, (_, i) => `main.normalizedClaimValues[${i}]`),
  ];
  const values = await witnessValues(circuit, w, names);
  return {
    KeyBindingX: values[0],
    KeyBindingY: values[1],
    normalizedClaimValues: values.slice(2),
  };
}

/** All 43-char base64url runs in `s`, as [startIndex, run]. */
function base64urlRuns(s: string, len = 43): Array<[number, string]> {
  const out: Array<[number, string]> = [];
  const re = /[A-Za-z0-9\-_]+/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s)) !== null) {
    for (let i = 0; i + len <= m[0].length; i++) out.push([m.index + i, m[0].slice(i, i + len)]);
  }
  return out;
}

describe("OpenAC JWT device-key path binding PoC", () => {
  let circuit!: WitnessTester<any, any>;

  before(async () => {
    circuit = await circomkit.WitnessTester(CIRCUIT_NAME, {
      file: "jwt",
      template: "JWT",
      params: CIRCUIT_PARAMS,
      recompile: true,
    });
    console.log("#constraints:", await circuit.getConstraintCount());
  });

  it("rejects a witness that re-aims KeyBindingX/Y at an attacker-planted base64url run", async () => {
    const atk = attackerKey();

    // The holder controls its own `sub` identifier. Planting the attacker's
    // uncompressed coordinates there puts two 43-char base64url runs into the
    // ISSUER-SIGNED payload without touching cnf.jwk.
    const mock = await generateMockData({
      circuitParams: CIRCUIT_PARAMS,
      subject: `did:key:z${atk.x}${atk.y}`,
    });

    const payload = atob(mock.token.split(".")[1]);
    const plantedX = payload.indexOf(atk.x);
    const plantedY = payload.indexOf(atk.y);
    assert.ok(plantedX > 0 && plantedY > 0, "planted runs must be present in the signed payload");

    // --- honest witness -------------------------------------------------
    const honest = mock.circuitInputs;
    assert.equal(honest.matchIndex[0], payload.indexOf('"x":"'));
    assert.equal(honest.matchLength[0], 5);
    const honestWitness = await circuit.calculateWitness(honest);
    await circuit.expectConstraintPass(honestWitness);
    const honestOut = await outputs(circuit, honestWitness);
    assert.equal(honestOut.KeyBindingX, base64urlToBigInt(mock.deviceKey.x));
    assert.equal(honestOut.KeyBindingY, base64urlToBigInt(mock.deviceKey.y));

    // --- malicious witness ----------------------------------------------
    // message / signature / claims / claimLengths / decodeFlags / matchesCount
    // are byte-for-byte identical. Only slots 0 and 1 move.
    const malicious = {
      ...honest,
      matchIndex: [...honest.matchIndex],
      matchLength: [...honest.matchLength],
      matchSubstring: honest.matchSubstring.map((s: bigint[]) => [...s]),
    };
    aimSlot(malicious, 0, payload, plantedX);
    aimSlot(malicious, 1, payload, plantedY);

    assert.deepEqual(malicious.message, honest.message);
    assert.equal(malicious.sig_r, honest.sig_r);
    assert.equal(malicious.sig_s_inverse, honest.sig_s_inverse);
    assert.deepEqual(malicious.claims, honest.claims);
    assert.equal(malicious.matchesCount, honest.matchesCount);

    // THE FIX: jwt.circom pins match slots 0/1 to the literal '"x":"' / '"y":"'
    // anchors (matchLength === 5 plus fixed bytes), so the length-1 re-aiming
    // trick no longer satisfies the circuit.
    await assert.rejects(
      () => circuit.calculateWitness(malicious),
      /Assert Failed/,
      "re-aimed device-key witness must be rejected",
    );
  });

  // --- Negative PoC: precondition boundary --------------------------------

  it("is UNSATISFIABLE when aimed at the zero-padded payload tail", async () => {
    const mock = await generateMockData({ circuitParams: CIRCUIT_PARAMS });
    const payload = atob(mock.token.split(".")[1]);

    const malicious = {
      ...mock.circuitInputs,
      matchIndex: [...mock.circuitInputs.matchIndex],
      matchLength: [...mock.circuitInputs.matchLength],
      matchSubstring: mock.circuitInputs.matchSubstring.map((s: bigint[]) => [...s]),
    };
    // K = last real payload byte (non-zero, so arrays.circom:222 passes),
    // xStartIndex = payload.length => the 43-byte window is all zeros.
    aimSlot(malicious, 0, payload, payload.length);

    await assert.rejects(
      () => circuit.calculateWitness(malicious),
      /Assert|Error/,
      "Base64Lookup (base64.circom:127) must reject 0x00 window bytes",
    );
  });

  it("degrades to unusable targets when the payload carries no attacker-controlled run", async () => {
    const mock = await generateMockData({ circuitParams: CIRCUIT_PARAMS });
    const payload = atob(mock.token.split(".")[1]);

    const known = new Set<string>([mock.deviceKey.x, mock.deviceKey.y, ...mock.hashedClaims]);
    const runs = base64urlRuns(payload);
    const usable = runs.filter(([, run]) => !known.has(run));

    // Off-by-one shifted windows exist, but every one of them decodes to a value
    // the attacker cannot produce a P-256 private key for. The exploit needs a
    // run the attacker CHOSE, i.e. a field they control that the issuer signs.
    const exact = runs.filter(([, run]) => known.has(run)).map(([, run]) => run);
    assert.ok(exact.includes(mock.deviceKey.x) && exact.includes(mock.deviceKey.y));
    const atk = attackerKey();
    assert.ok(!usable.some(([, run]) => run === atk.x || run === atk.y));
    console.log(
      `no-plant payload: ${runs.length} reachable 43-char windows, ` +
        `${exact.length} are the real cnf coords / _sd digests, ` +
        `0 are attacker-chosen (no private key => no device-binding forgery)`,
    );
  });
});

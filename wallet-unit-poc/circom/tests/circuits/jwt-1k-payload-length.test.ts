import assert from "assert";
import { sha256Pad } from "@zk-email/helpers";
import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";

// Exact jwt_1k parameters from circuits.json: JWT(1280, 960, 4, 50, 128)
const MAX_MESSAGE_LENGTH = 1280;
const MAX_B64_PAYLOAD_LENGTH = 960;
const HEADER = Buffer.from(JSON.stringify({ alg: "ES256", typ: "vc+sd-jwt" })).toString("base64url");

function buildPayloadFixture(targetB64PayloadLength: number) {
  const emptyPayloadLen = JSON.stringify({ sub: "example", pad: "" }).length;
  // Choose raw JSON byte length so base64url (unpadded) has exact length targetB64PayloadLength
  // (works whenever targetB64PayloadLength % 4 !== 1).
  const rawPayloadLen = Math.floor((targetB64PayloadLength * 3) / 4);
  const pad = "a".repeat(rawPayloadLen - emptyPayloadLen);
  const payload = Buffer.from(JSON.stringify({ sub: "example", pad }));
  const encoded = payload.toString("base64url");
  assert.strictEqual(encoded.length, targetB64PayloadLength);

  const raw = Buffer.from(`${HEADER}.${encoded}`, "ascii");
  assert.ok(raw.length <= 1271, `raw length ${raw.length} must fit 1k padded capacity 1280`);
  const [message, messageLength] = sha256Pad(raw, MAX_MESSAGE_LENGTH);
  assert.ok(messageLength <= MAX_MESSAGE_LENGTH);

  return {
    input: {
      message: Array.from(message),
      messageLength,
      periodIndex: HEADER.length,
    },
    rawLength: raw.length,
    encodedLength: encoded.length,
    payload,
  };
}

describe("JWT 1k PayloadExtractor encoded payload length vs 1k signing capacity", () => {
  let circuit!: WitnessTester<["message", "messageLength", "periodIndex"], ["payload"]>;

  before(async () => {
    circuit = await circomkit.WitnessTester("JWT1kPayloadExtractorBound", {
      file: "jwt_tx_builder/header-payload-extractor",
      template: "PayloadExtractor",
      params: [MAX_MESSAGE_LENGTH, MAX_B64_PAYLOAD_LENGTH],
      recompile: true,
    });
  });

  it("decodes a 960-char Base64url payload cleanly within jwt_1k", async () => {
    const { input, payload } = buildPayloadFixture(960);
    assert.strictEqual(payload.length, 720);
    await circuit.expectPass(input, { payload: Array.from(payload) });
  });

  it("accepts a 1026-char Base64url payload (1,071 signing bytes <= 1,271) in jwt_1k", async () => {
    // 44-byte header + '.' + 1026-byte Base64url payload = 1,071 signing bytes (padded to 1,152 <= 1,280).
    // SelectSubArrayBase64(1280, 960) uses GreaterThan(10), whose Num2Bits(11) enforces
    // b64PayloadLength <= 1024 (proved in Jwt1kPayloadLengthBound.lean), so 1026 fails in-circuit.
    const { input, rawLength, encodedLength } = buildPayloadFixture(1026);
    assert.strictEqual(encodedLength, 1026);
    assert.ok(rawLength <= 1271);

    const witness = await circuit.calculateWitness(input);
    await circuit.expectConstraintPass(witness);
  });
});

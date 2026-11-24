import assert from "assert";
import { sha256Pad } from "@zk-email/helpers";
import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";

const MAX_MESSAGE_LENGTH = 2048;
const MAX_BASE64_PAYLOAD_LENGTH = 2000;
const EXTRACTOR_FILE = "jwt_tx_builder/header-payload-extractor";
const HEADER = Buffer.from(JSON.stringify({ alg: "ES256", typ: "JWT", kid: "issuer" })).toString("base64url");
const PERIOD = ".".charCodeAt(0);

function signingFixture(signingLength: number) {
  const encodedLength = signingLength - HEADER.length - 1;
  const emptyPayloadLength = JSON.stringify({ sub: "example", description: "" }).length;
  const description = "a".repeat(Math.floor(encodedLength * 3 / 4) - emptyPayloadLength);
  const payload = Buffer.from(JSON.stringify({ sub: "example", description }));
  const encoded = payload.toString("base64url");
  const raw = Buffer.from(`${HEADER}.${encoded}`, "ascii");
  const [message, messageLength] = sha256Pad(raw, MAX_MESSAGE_LENGTH);

  assert.strictEqual(raw.length, signingLength);
  assert.ok(encoded.length < MAX_BASE64_PAYLOAD_LENGTH);
  assert.strictEqual(raw[HEADER.length], PERIOD);
  assert.strictEqual(raw.filter((byte) => byte === PERIOD).length, 1);
  assert.strictEqual(message[raw.length], 0x80);
  assert.strictEqual(Buffer.from(message).readBigUInt64BE(messageLength - 8), BigInt(signingLength * 8));

  return { input: { message: Array.from(message), messageLength, periodIndex: HEADER.length }, payload };
}

describe("JWT 2k PayloadExtractor SHA-256 padding", () => {
  let circuit: WitnessTester<["message", "messageLength", "periodIndex"], ["payload"]>;

  before(async () => {
    circuit = await circomkit.WitnessTester("JWT2kPayloadExtractor", {
      file: EXTRACTOR_FILE,
      template: "PayloadExtractor",
      params: [MAX_MESSAGE_LENGTH, MAX_BASE64_PAYLOAD_LENGTH],
      recompile: true,
    });
  });

  const cases = [
    { raw: 1471, padded: 1536 },
    { raw: 1472, padded: 1536, paddingHasPeriod: true },
    { raw: 1503, padded: 1536, paddingHasPeriod: true },
    { raw: 1504, padded: 1536 },
    { raw: 1975, padded: 1984 },
  ];

  for (const { raw, padded, paddingHasPeriod = false } of cases) {
    it(`decodes ${raw} signing bytes padded to ${padded} bytes`, async () => {
      const { input, payload } = signingFixture(raw);
      assert.strictEqual(input.messageLength, padded);
      assert.strictEqual(input.message[padded - 2] === PERIOD, paddingHasPeriod);
      assert.strictEqual(input.message.filter((byte) => byte === PERIOD).length, paddingHasPeriod ? 2 : 1);

      const expected = Buffer.alloc(MAX_BASE64_PAYLOAD_LENGTH * 3 / 4);
      expected.set(payload);
      await circuit.expectPass(input, { payload: Array.from(expected) });
    });
  }

  it("rejects a padded length of 2048 in the JWT 2k profile", async () => {
    const { input } = signingFixture(1976);
    assert.strictEqual(input.messageLength, MAX_MESSAGE_LENGTH);
    assert.strictEqual(input.message.filter((byte) => byte === PERIOD).length, 1);

    const diagnostic = await circuit.expectFail(input);
    assert.match(diagnostic, /Error in template Num2Bits_\d+ line:/);
    assert.match(diagnostic, /Error in template PayloadExtractor_\d+ line:/);
  });
});

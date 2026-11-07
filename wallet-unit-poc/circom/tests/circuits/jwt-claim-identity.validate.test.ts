import { strict as assert } from "assert";
import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";
import { generateMockData } from "../../src/mock-vc-generator.ts";
import { witnessValues } from "../common/witness-signals.ts";

// Validation for Items 1 + 3 (Option B: no off-circuit hashing).
// jwt.circom derives claimIdentifierHashes[i] = H(name_i) over a fixed 31-byte
// width. Show recomputes H(verifier_name) over the SAME width from the raw name
// bytes. This test proves the credential-side hash equals a standalone
// HashBytesToFieldWithLen(31) of the same name -- i.e. Show's hash will match
// by construction, with no Poseidon reimplemented off-circuit.
const CIRCUIT_PARAMS = [2048, 2000, 4, 50, 128];
const MAX_CLAIMS = CIRCUIT_PARAMS[2] - 2;
const NAME_ID_LEN = 31;

function nameBuffer(name: string): bigint[] {
  const bytes = Array.from(Buffer.from(name, "utf8")).map((b) => BigInt(b));
  assert.ok(bytes.length <= NAME_ID_LEN, `name "${name}" exceeds ${NAME_ID_LEN}`);
  while (bytes.length < NAME_ID_LEN) bytes.push(0n);
  return bytes;
}

describe("JWT claim-identity binding (Items 1+3, Option B)", () => {
  let jwt!: WitnessTester<any, any>;
  let hasher!: WitnessTester<any, any>;

  before(async () => {
    jwt = await circomkit.WitnessTester("JWTClaimIdentityValidate", {
      file: "jwt",
      template: "JWT",
      params: CIRCUIT_PARAMS,
      recompile: true,
    });
    hasher = await circomkit.WitnessTester("NameHash31", {
      file: "keyless_zk_proofs/hashtofield",
      template: "HashBytesToFieldWithLen",
      params: [NAME_ID_LEN],
      recompile: true,
    });
  });

  it("derives per-slot identity that matches a standalone H(name) (Show's hash)", async () => {
    // Default claims: slot0 name="name", slot1 name="roc_birthday".
    const mock = await generateMockData({
      circuitParams: CIRCUIT_PARAMS,
      claimFormats: [4, 3],
    });
    const w = await jwt.calculateWitness(mock.circuitInputs);
    await jwt.expectConstraintPass(w);

    const names = Array.from(
      { length: MAX_CLAIMS },
      (_, i) => `main.claimIdentifierHashes[${i}]`,
    );
    const derived = await witnessValues(jwt, w, names);

    // Independently hash "roc_birthday" (slot 1) the way Show will.
    const hw = await hasher.calculateWitness({
      in: nameBuffer("roc_birthday"),
      len: 12n,
    });
    const [standalone] = await witnessValues(hasher, hw, ["main.hash"]);

    assert.equal(
      derived[1],
      standalone,
      "credential-derived identity must equal Show's standalone H(name)",
    );
    assert.notEqual(derived[1], 0n, "active slot identity must be non-zero");
  });
});

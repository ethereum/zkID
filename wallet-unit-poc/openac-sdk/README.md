# openac-sdk

ZK proof SDK for SD-JWT credentials. Prove predicates (`age >= 18`, `balance <= credit_limit`, etc.) without revealing claim values. Built on Spartan2 + Hyrax over secp256r1.

## Install

```bash
npm install openac-sdk
```

Node 18+. Browser usage requires preloading WASM and passing `wasmModule` to `OpenAC.init`.

## Quickstart

```typescript
import {
  OpenAC,
  compilePredicateExpression,
  requiredNormalization,
} from "openac-sdk";

const openac = await OpenAC.init();
const keys = await openac.loadKeysFromUrl("1k");

const predicate = {
  claim: "roc_birthday",
  op: "<=" as const,
  value: new Date("2008-01-01"),
};

// Precompute once per credential. Pass the predicate so format inference works.
const precomputed = await openac.precompute({
  jwt: sdJwtToken,
  disclosures: ["WyJzYWx0...", "..."],
  issuerPublicKey: { kty: "EC", crv: "P-256", x: "...", y: "..." },
  keys,
  predicates: predicate,
});

// Present per verifier session.
const proof = await openac.present({
  precomputed,
  verifierNonce: "challenge-123",
  devicePrivateKey: "0xabcdef...",
  keys,
  predicates: predicate,
});

// The verifier compiles its policy once against its credential schema.
const compiled = compilePredicateExpression(predicate, schemaClaims);

// Verify against the statement the verifier required: its own nonce and its own
// policy, both supplied by the verifier rather than taken from the presentation.
const result = await openac.verify(proof, keys.verifyingKeys(), {
  nonce: "challenge-123",
  predicates: compiled.predicates,
  logicExpression: compiled.logicExpression,
  claimNormalization: requiredNormalization(compiled),
});

// verify() reports the issuer key rather than judging it, so check it against
// the issuers you trust. See "Verifier" below.
if (!result.valid || !result.issuerKey) throw new Error(result.error);
if (!myTrustStore.isTrustedIssuer(result.issuerKey.jwk)) throw new Error("untrusted issuer");

console.log(result.expressionResult);
```

## Predicates

```typescript
// Literal comparison
{ claim: "age", op: ">=", value: 18 }

// Date (auto-encoded to ROC date format)
{ claim: "roc_birthday", op: "<=", value: new Date("2008-01-01") }

// Claim-to-claim
{ claim: "balance", op: "<=", compareTo: { claim: "credit_limit" } }

// Nested boolean composition
{
  all: [
    { claim: "age", op: ">=", value: 18 },
    {
      any: [
        { claim: "kyc_tier", op: "==", value: 2 },
        { claim: "kyc_tier", op: "==", value: 3 },
      ],
    },
  ],
}
```

**Operators**: `"<="`, `">="`, `"=="`
**Value types**: `bigint`, `number`, `Date`, `string`
**Combinators**: `all`, `any`, `not` (nest arbitrarily)
**Format**: inferred from value type (`Date` becomes date, numeric becomes uint, string becomes string). Override with `format: "date" | "uint" | "string"` on any predicate.

### Precompute decides what a presentation can prove

`precompute()` runs the JWT circuit once and caches the claim values it normalized. `present()` reuses that cache, so the predicates passed to `precompute()` fix what later presentations can evaluate:

- a claim no precompute-time predicate referenced was never decoded, and its cached value is `0` rather than the credential's value
- a claim normalized as `uint` is a decimal integer and is not comparable to a `date` or `string` predicate

The prover chooses this normalization, so it is part of what a verifier must check rather than something the SDK can settle on the holder's side alone. It is enforced in two places:

- `present()` compares its compiled formats against the ones recorded at precompute time and throws `CLAIM_FORMAT_MISMATCH` rather than building a proof over values that do not answer its predicates
- `verify()` reads `decodeFlags` and `claimFormats` out of the Prepare proof's public IO and requires them to match `expected.claimNormalization`, so a prover that skips the check above still cannot get a policy accepted that was evaluated over `0` or over a differently normalized value

Reuse a `PrecomputedCredential` across sessions only for predicates over the same claims in the same formats; otherwise call `precompute()` again. If your verifiers use varying policies, pass the union of the claims and formats you expect to serve to `precompute()`. Each extra decoded claim costs constraints, so precompute for the policies you serve rather than for the whole credential.

## Verifier

A verifier only needs the two verifying keys, not the proving keys.

```typescript
import {
  OpenAC,
  compilePredicateExpression,
  requiredNormalization,
} from "openac-sdk";

const openac = await OpenAC.init();

// The verifier compiles its own policy once, against its credential schema.
const compiled = compilePredicateExpression(predicate, schemaClaims);

const result = await openac.verify(
  proof,
  {
    prepareVerifyingKey, // Uint8Array
    showVerifyingKey,    // Uint8Array
  },
  {
    nonce,                                    // the challenge this session issued
    predicates: compiled.predicates,
    logicExpression: compiled.logicExpression,
    claimNormalization: requiredNormalization(compiled),
  },
);
// result.valid            proofs verified, bound to this nonce and policy
// result.expressionResult  boolean output of the predicate expression
// result.issuerKey         the key the credential was signed under; check it
// result.deviceKey         always null; binding flows through comm_W_shared
```

`verify` passes when all of these hold:

1. **Shared commitment**: byte-equality of `comm_W_shared` between the Prepare and Show instances, tying both proofs to the same underlying credential.
2. **Both SNARKs verify** against the supplied verifying keys.
3. **Statement binding**: the Show proof's public values must equal what the verifier recomputes from its own `nonce` (freshness/replay) and compiled policy (no policy swap).
4. **Claim normalization**: the `decodeFlags` and `claimFormats` in the Prepare proof's public IO must match what the policy requires, so the policy was evaluated over the credential's claim values in the formats it compares against rather than over `0` or a differently normalized value.

### Issuer trust is yours to enforce

Note what the list above does **not** include: who issued the credential.

The circuit verifies the credential signature against whatever issuer key was supplied at proving time. A holder can generate their own P-256 key, sign a credential with any claim values they want, and produce a presentation that verifies with `valid: true` and `expressionResult: true`.

`result.issuerKey` is the key the proof was built under. It is read out of the Prepare proof's public IO, so a prover cannot report one key while proving under another. The SDK reports it and leaves the decision to you, so you can resolve trust however your deployment needs:

```typescript
const result = await openac.verify(proof, vks, expected);
if (!result.valid || !result.issuerKey) return reject(result.error);

// issuerKey is given in both forms; use whichever matches your trust store.
// It is non-null whenever valid is true; the check above narrows the type.
const { x, y, jwk } = result.issuerKey;   // bigint coords + canonical P-256 JWK

const issuer = await myTrustStore.lookup(jwk);   // your logic, async is fine
if (!issuer || issuer.revoked) return reject("untrusted issuer");

// Only now is expressionResult meaningful.
return result.expressionResult;
```

Resolve the expected issuer from your own configuration, by expected `iss`/`kid`/credential type, rather than from anything the holder sent alongside the proof.

## Configuration

```typescript
const openac = await OpenAC.init({
  keysBaseUrl: "https://my-cdn.example/keys", // override the default R2 endpoint
  assetsDir: "./assets",                       // override circuit-WASM asset path
  wasmModule: preloadedWasm,                   // browser: pre-init WASM and pass it
});
```

## Testing helpers

```typescript
import { generateDummyCredential } from "openac-sdk/testing";

const cred = generateDummyCredential({
  size: "1k",
  claims: [
    { key: "roc_birthday", value: "0900101" },
    { key: "roc_max", value: "0950101" },
  ],
});
// cred.jwt, cred.disclosures, cred.issuerPublicKey, cred.devicePrivateKeyHex
```

Deterministic keys; JWT is sized to fit the chosen circuit slot.

## API

| Method | Returns |
|---|---|
| `OpenAC.init(config?)` | `Promise<OpenAC>` |
| `openac.loadKeysFromUrl(size, url?)` | `Promise<KeySet>` |
| `openac.loadKeys(serialized)` | `Promise<KeySet>` |
| `openac.precompute(req)` | `Promise<PrecomputedCredential>` |
| `openac.present(req)` | `Promise<PresentationProof>` |
| `openac.verify(proof, vks, expected)` | `Promise<VerificationResult>` |
| `openac.verifyProof(serialized, vks, expected)` | `Promise<VerificationResult>` |

`expected` is an `ExpectedStatement`: `{ nonce, predicates, logicExpression, claimNormalization }`. All four come from `compilePredicateExpression` plus your own nonce. Every verify call returns `issuerKey` for the caller to check. See [Issuer trust is yours to enforce](#issuer-trust-is-yours-to-enforce).

`size` is `"1k" | "2k" | "4k" | "8k"`. `precompute` auto-picks the smallest size that fits the JWT.

## Build

```bash
pnpm install
pnpm build:all     # WASM (needs Rust + wasm-pack) + TypeScript
pnpm test
```

## Dependencies

`@noble/curves` and `@noble/hashes`. The SDK loads circuit assets and the WASM module from disk via Node's `fs`/`path`/`url` builtins, so Node 18+ is required for the default initialization path.

## License

MIT

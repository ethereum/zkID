# zkID web demo

Runs the OpenAC pipeline in the browser: generate a test credential, prove,
present and verify, using the SDK's WASM verifier.

## Setup

```
npm install
npm run setup   # copies generated assets, see below
npm run dev
```

`npm run setup` (`scripts/copy-assets.sh`) fails with a message if a source is
missing. It builds nothing; build the SDK first (`openac-sdk/wasm/pkg` and
`openac-sdk/assets`) and generate the keys in `ecdsa-spartan2/keys`.

## Generated files are not tracked

These are copied from the SDK and ignored by git:

- `public/openac_wasm_bg.wasm`, `src/wasm/*` (verifier, from `openac-sdk/wasm/pkg`)
- `public/jwt.wasm` (from `circom/build/jwt_1k`; run `yarn compile:jwt:1k` in `circom` first)
- `public/show.wasm` (from `openac-sdk/assets`)
- `public/keys` (link to `ecdsa-spartan2/keys`)

They used to be committed, which let the demo run a verifier older than the
SDK. At startup `src/pipeline.ts` now calls the module's `abi_version()` and
refuses to continue unless it is 1.

`public/keys` was committed as a symlink to an absolute path on one
developer's machine, so it was broken everywhere else. The setup script now
creates it as a relative link.

The demo loads 1k keys; `jwt.wasm` must be the 1k circuit that matches them. Do not use
`openac-sdk/assets/jwt.wasm`: it is the default circuit, whose `message` input
is 1920 long, not 1280.

# Security policy

## Status of this code

This code is a reference implementation. It has not been checked for production quality.

Only an internal audit has been completed. The code has not had an external audit.

## Reporting a vulnerability

Please report security issues privately. Do not open a public issue, pull request or discussion for them.

- Preferred: use "Report a vulnerability" under the repository's Security tab. This opens a private advisory that only the maintainers can read.
- Alternative: email epic@ethereum.org.

A useful report includes:

- the commit or tag you tested;
- the component (circuits, Rust prover and verifier, SDK, mobile bindings, or specs);
- what an attacker can do, and what they need to do it;
- steps or a test that reproduces it.

If you are not sure whether something is a security issue, report it privately and we will tell you.

## What to expect

- We acknowledge a report within 3 working days.
- We tell you whether we accept the finding and what we plan to do within 7 working days.
- We agree a disclosure date with you before publishing a fix or an advisory.
- We credit reporters in the advisory unless they ask us not to.

## Scope

In scope:

- soundness of the circuits: a proof that verifies for a statement that is false;
- privacy of a presentation: anything that lets verifiers link two presentations of one credential, or learn an attribute the holder did not disclose;
- the verifier in the SDK or the mobile bindings accepting a presentation it should reject;
- a flaw in a dependency, where it affects the proofs or the verifier in this repository.

Out of scope:

- the demo applications and their hosting;
- denial of service that needs no more than sending large inputs;
- issues that need a compromised device or a compromised issuer key, unless the code makes the impact worse than it has to be.

## Supported versions

Reports are welcome against `main` and the latest tagged release. Earlier tags do not receive fixes.

A fix that changes a circuit comes with a new set of proving and verification keys. Keys from before the fix stop working with the fixed code.

## Known limitations

Some checks are left to the wallet and the verifier by design. For example, the verifier decides which issuer keys to trust, and issues a fresh nonce for each request. The SDK README describes these. They are documented behaviour, and we still want to hear about them if the code or the documentation makes them easy to get wrong.

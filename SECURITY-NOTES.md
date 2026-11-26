# Security notes

These are the limits of what the OpenAC circuits and SDK enforce. Each section
says who must cover the gap and what the planned fix is. The notes assume the
OpenAC findings fixes are merged.

## Credential validity is not part of the proof

`verify()` does not check `exp` or `nbf`. The SDK checks them only on the
holder side, with a clock the caller picks, and that check is not part of the
proof. The relying party must check the validity period itself, with its own
clock.

The planned fix is to check `exp` and `nbf` in Show against a public `now`.
That needs new Show keys.

## Sparse claim schemas cost space

Claim arrays are sized up to the highest slot a predicate reads, so gaps in
slot numbers still cost space. The verifier fails closed when a slot the
policy reads has no expected format. No fix is planned. Dense slot numbers
avoid the cost.

## Dates are checked for form, not for existence

The circuit checks only the `YYYY-MM-DD` form and the `-` separators, so
`2024-13-45` passes. Neither the circuit nor the SDK checks that the date
exists. A verifier that needs a real calendar date must check the claim
itself.

## Low-S device signatures are a prover rule

Proved device signatures must be low-S. The SDK signs low-S and turns a
high-S input into low-S before proving. The circuit can't check this, because
`s` is a private witness, so other provers must follow the rule themselves.

The planned fix is to enforce low-S in Show at the next Show key update.

## Claim-to-claim predicates don't compare formats

The verifier checks the format of each side on its own. It does not check that
both sides use the same format. This matters only for a hand-built expected
normalization, since the compiler already enforces it for holder policies. The
planned fix is a format match check in the verifier.

## An empty string reads as zero

An empty `string` claim normalizes to 0, the same as a zero value, so a policy
can't tell the two apart. The planned fix is a non-empty check or a length tag
in the string normalizer at the next Prepare key update.

## Revocation secrets need high entropy

`r` must be uniform random with at least 128 bits of entropy, and must never be
derived from identifiers. Whoever creates `r`, the holder or the issuer, must
ensure this. No code here checks it. If a deployment can't guarantee it, use a
hiding commitment instead. See
`revocation/Privacy-Preserving-Credential-Revocation.md`.

## A WASM trap poisons the module

A trap leaves the WASM module in an unknown state. After a trap, `WasmBridge`
marks the module poisoned, and every later call throws `WASM_POISONED`, even
from a new bridge on the same module. Callers must not catch this error and
carry on. They should load a new module or worker, and the web demo should do
the same after `WASM_POISONED`.

# Security notes

Boundaries the OpenAC circuits and SDK do not enforce, who must enforce them,
and what a future fix would be. Finding ids are from the zkID OpenAC review.

Checks named here (circuit constraints, SDK error codes, the low-S flip, the
WASM guards) are the ones added by the OpenAC findings fixes. A tree without
those fixes does not enforce them.

## Validity clock (1789507490)

`verify()` does not attest `exp` or `nbf`. The SDK checks them on the holder
side only, against a caller-supplied or local clock, and that check is not part
of the proven statement. The relying party MUST check the credential's validity
period itself, against its own clock.

Future fix: carry `exp` and `nbf` through the shared witness and compare them
with a public `now` in Show. This changes the Show circuit and needs new Show
keys.

## Sparse claim schemas (1789511071)

The SDK sizes the claim vectors (`decodeFlags`, `claimFormats`) by the highest
slot a predicate reads, not by the number of claims, so a sparse schema costs
the full width up to that index. The verifier enforces the boundary: it fails
closed when a slot the policy reads has no expected format in the
normalization it was given.

Follow-up: none planned; a denser slot assignment would avoid the cost.

## iso_date calendar validity

`iso_date` values are checked for their lexical form (`-` separators, digits in
the `YYYY-MM-DD` positions) in the circuit, not for calendar validity (month
13, day 31 in a 30-day month). Nothing checks calendar validity: neither the
circuit nor the SDK. A verifier that needs valid dates must check the date
claim itself.

The profile text is in `specs/1-openac/README.md`.

## Low-S device signatures (1789513951)

Proved device signatures MUST be low-S. An implementation MUST NOT emit
high-S signatures, and one that receives a high-S signature from a signer
MUST normalize it to low-S before proving or reject it. The SDK normalizes
(`hasHighS()` then `normalizeS()` in the Show input builder).

The signature's `s` is a private witness, so the circuit does not enforce
this and a verifier cannot tell from the proof. It is a prover-implementation
obligation today.

Follow-up: enforce low-S in the Show circuit at the next Show key
regeneration.

## Claim-to-claim predicates

`checkPredicateFormats` checks each side of a claim-to-claim predicate on its
own, not that both sides use the same format. This only matters if a verifier
hand-builds its expected normalization; the compiler enforces it for the
holder's policy.

Follow-up: check that the two formats are equal in the verifier.

## Empty string values

Under the string format an empty value normalizes to 0. An empty signed string
and the absent or zero encoding therefore coincide for string-format equality.
A policy that compares a string claim to an empty or zero-packed literal cannot
tell the two apart.

Follow-up: add a non-empty check or a length tag to the string normalizer at
the next Prepare key regeneration.

## Revocation commitments (1789503260)

See `revocation/Privacy-Preserving-Credential-Revocation.md`, Commitments:
`r` must be uniform with at least 128 bits of entropy, or the commitment must
be hiding. Whoever creates `r` (the holder or the issuer, per deployment)
enforces this; no code here checks it.

Follow-up: if a deployment cannot guarantee entropy, adopt a blinded
(Pedersen-style) commitment in the revocation design.

## WASM traps (1789511095)

A trap (unreachable, out of bounds, stack overflow) inside the verifier or
prover WASM leaves the module in an undefined state. Treat any runtime trap as
fatal to that module instance or worker: discard it and create a new one. Do
not retry on the same instance.

The SDK's `WasmBridge` does this: after a trap the module is poisoned and every
later call throws `WASM_POISONED`, including from a fresh bridge over the same
glue. Recovery needs a new module instance or worker. This fails closed and
only costs availability. Callers that wrap the bridge must not catch that error
and carry on.

Follow-up: none; the web demo should create a new module or worker after
`WASM_POISONED`.

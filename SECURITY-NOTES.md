# Security notes

Boundaries the OpenAC circuits and SDK do not enforce, who must enforce them,
and what a future fix would be. Finding ids are from the zkID OpenAC review.

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

## Accepted circuit grammar limits

The Prepare circuit parses the credential with a fixed grammar. It enforces
these:

- Disclosures are compact JSON three-string arrays with no whitespace.
- `cnf.jwk` is a flat object (no nested objects or arrays), checked inside the
  region that follows the literal `"cnf":{"jwk":{`.
- `_sd` is a flat array, checked inside the region that follows `"_sd":[`.
- A disclosure's base64 form is 56 to 119 characters long.
- `iso_date` values are checked for their lexical form in the circuit, not
  for calendar validity (month 13, day 31 in a 30-day month). Nothing checks
  calendar validity: neither the circuit nor the SDK. A verifier that needs
  valid dates must check the date claim itself.

The circuit does not parse JSON structure. It counts only the exact compact
literals `"cnf":{"jwk":{` and `"_sd":[`, and does not know which object holds
them. So the issuer MUST NOT sign a payload that breaks any of these
preconditions:

- The payload contains exactly one compact `"cnf":{"jwk":{` occurrence (no
  whitespace). It is the holder key binding, `jwk` is the first member of that
  `cnf`, and the jwk object is flat. If the real `cnf` is serialized any other
  way (another member first, or whitespace) while a nested object elsewhere
  contains a compact `"cnf":{"jwk":{`, the nested one is the only match and the
  device key is whatever that object holds.
- No other object in the payload contains `cnf.jwk`.
- The payload contains exactly one `_sd` array, serialized compactly as
  `"_sd":[`. It is the credential's disclosure array, wherever the profile
  places it (the shipped credentials use `vc.credentialSubject._sd`), and it is
  flat. No other object carries an `_sd` array, such as a nested `address._sd`.
- Claim names in the issuer's schema are unique (see "Duplicate claim names").

The SDK rejects non-compact disclosures before proving
(`Invalid disclosure format ... expected compact JSON with no whitespace`).
`assertUnambiguousPayload` (`AMBIGUOUS_PAYLOAD`, in
`openac-sdk/src/inputs/payload-anchors.ts`) rejects a payload that has no
P-256 `cnf.jwk`, whose `"x":"` or `"y":"` anchor does not occur exactly once
or does not directly precede the `cnf.jwk` coordinate, that does not contain
exactly one `"_sd":[` anchor, or in which a disclosure digest does not occur
exactly once, quoted, inside that `_sd` array. It does not parse JSON, so it
does not check that `cnf.jwk` is first in `cnf` or that the `_sd` array is the
credential's disclosure array rather than one nested in another object. This pre-check rejects some of the layouts above for honest
holders, but a malicious holder can build witnesses without the SDK, so the
issuer must not sign such payloads. The 56 to 119 character disclosure window
has no SDK check; a disclosure outside it fails when the witness is built or
the circuit is run, not with a dedicated error.

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

## Duplicate claim names (1789504910)

If two disclosures share a claim name, a holder can still omit one of them and
present the other. The circuit cannot tell which was meant. This residual is
why the profile forbids duplicate claim names. The SDK rejects them at the
credential layer (`DUPLICATE_CLAIM`) and in claim schemas.

The circuit's `DistinctClaimNames` constraint rejects two active slots that
share a name in the proved identifiers. It cannot see a duplicate the holder
leaves out of the proof, so unique names stay a profile requirement on issuers.
A verifier cannot see the SDK check, so issuers must be trusted to follow it.

Follow-up: none.

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

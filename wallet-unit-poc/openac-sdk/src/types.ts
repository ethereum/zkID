export interface OpenACConfig {
  wasmPath?: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  wasmModule?: any;
  assetsDir?: string;
  artifacts?: CircuitArtifacts;
  memory?: { initial?: number; maximum?: number };
  keysBaseUrl?: string;
}

export interface CircuitArtifacts {
  prepareR1cs?: Uint8Array | string;
  showR1cs?: Uint8Array | string;
  prepareWitnessWasm?: Uint8Array | string;
  showWitnessWasm?: Uint8Array | string;
}

export interface JwtCircuitParams {
  maxMessageLength: number;
  maxB64PayloadLength: number;
  maxMatches: number;
  maxSubstringLength: number;
  maxClaimLength: number;
}

export interface ShowCircuitParams {
  nClaims: number;
  maxPredicates: number;
  maxLogicTokens: number;
  valueBits: number;
  /** Max issuer registry depth (issuer hiding). */
  maxIssuerDepth: number;
}

export const DEFAULT_JWT_PARAMS: JwtCircuitParams = {
  maxMessageLength: 1920,
  maxB64PayloadLength: 1900,
  maxMatches: 4,
  maxSubstringLength: 50,
  maxClaimLength: 128,
};

export const DEFAULT_SHOW_PARAMS: ShowCircuitParams = {
  nClaims: 2,
  maxPredicates: 2,
  maxLogicTokens: 8,
  valueBits: 64,
  maxIssuerDepth: 8,
};

export interface EcdsaPublicKey {
  kty: "EC";
  crv: "P-256";
  x: string; // base64url-encoded X coordinate
  y: string; // base64url-encoded Y coordinate
  kid?: string;
}

export type EcdsaPrivateKey = string | Uint8Array;

export interface PemPublicKey {
  pem: string;
}

export type IssuerPublicKey = EcdsaPublicKey | PemPublicKey;

export interface ProofPublicValues {
  /**
   * The only thing a verifier learns. Claim values are deliberately absent:
   * they are private predicate operands carried in the shared witness
   * commitment, not proof outputs.
   */
  expressionResult: boolean;
}

export interface VerifyingKeys {
  prepareVerifyingKey: Uint8Array;
  showVerifyingKey: Uint8Array;
}

/**
 * The verifier's expected statement, required by all verification APIs. The
 * verifier recomputes the Show proof's public values (nonce hash + predicate
 * program) from this and rejects any proof whose public values do not match, so
 * a valid proof also confirms it was produced for exactly this nonce and this
 * policy, not merely that some hidden predicate over the linked credential was
 * true for some hidden nonce.
 *
 * The verifier authors the policy and issues the nonce, so it supplies the
 * predicate program in the circuit's own (claim-index) terms. It does NOT take
 * the holder's disclosed claims: the statement the verifier requires is decided
 * by the verifier, independent of anything the holder discloses. A verifier that
 * prefers the name-based DSL can compile it once against its credential schema
 * via `compilePredicateExpression` and reuse the resulting `predicates` /
 * `logicExpression` here.
 *
 * Covers freshness, policy, and the claim normalization the policy is evaluated
 * over. The issuer is hidden: `verify()` reports the issuer registry root, and
 * `isValidIssuerRoot` (or the caller) must check it, e.g. against
 * `OpenACIssuerRegistry.isValidRoot` on chain.
 */
export interface ExpectedStatement {
  /** The exact nonce/challenge the verifier issued for this session (freshness). */
  nonce: string;
  /** The required predicate program, in circuit (claim-index) form. */
  predicates: import("./inputs/show-input-builder.js").PredicateSpec[];
  /** Postfix logic expression over predicate results (REF/AND/OR/NOT). */
  logicExpression: Array<{ type: number; value: number }>;
  /**
   * How each claim the policy reads must have been normalized by the credential
   * circuit: decoded (`decodeFlags[i] === 1`) and under the format the policy
   * compares against.
   *
   * The proof carries the normalization it was built under in its public IO,
   * and `verify()` requires the two to agree. Only the slots this requires are
   * checked, so a credential prepared for a wider set of predicates than this
   * policy reads still verifies.
   *
   * `compilePredicateExpression` returns exactly these arrays as `decodeFlags`
   * and `claimFormats`.
   */
  claimNormalization: ClaimNormalization;
  /**
   * Accepts or rejects the issuer registry root the proof was built against.
   * When omitted, the root is only reported on the result.
   */
  isValidIssuerRoot?: (issuerRoot: bigint) => boolean | Promise<boolean>;
}

export interface VerificationResult {
  /**
   * The proofs verified and are bound to the expected nonce and policy, and the
   * issuer root passed `isValidIssuerRoot` when one was given.
   */
  valid: boolean;
  expressionResult: boolean | null;
  /**
   * Root of the issuer registry the credential's issuer was proven to be in.
   * Non-null exactly when `valid` is true. Without `isValidIssuerRoot`, check
   * it yourself: a root the holder built from their own key also verifies.
   */
  issuerRoot: bigint | null;
  /** Always null. The device-key binding flows through comm_W_shared, not a public output. */
  deviceKey: null;
  verifyMs: number;
  error?: string;
}

export interface KeySet {
  prepareProvingKey: Uint8Array;
  prepareVerifyingKey: Uint8Array;
  showProvingKey: Uint8Array;
  showVerifyingKey: Uint8Array;
  verifyingKeys(): VerifyingKeys;
  serialize(): SerializedKeySet;
}

export interface SerializedKeySet {
  prepareProvingKey: Uint8Array;
  prepareVerifyingKey: Uint8Array;
  showProvingKey: Uint8Array;
  showVerifyingKey: Uint8Array;
}

export interface SerializedProofJSON {
  version: string;
  prepareProof: string; // base64
  showProof: string; // base64
  prepareInstance: string; // base64
  showInstance: string; // base64
  publicValues: {
    expressionResult: boolean;
  };
}

export type SerializedProof = Uint8Array;

export type ErrorCode =
  | "SETUP_FAILED"
  | "KEYS_NOT_FOUND"
  | "PROOF_GENERATION_FAILED"
  | "WITNESS_GENERATION_FAILED"
  | "REBLIND_FAILED"
  | "VERIFICATION_FAILED"
  | "INVALID_PROOF_FORMAT"
  | "COMMITMENT_MISMATCH"
  | "INVALID_JWT"
  | "INVALID_KEY"
  | "INVALID_SIGNATURE"
  | "MISSING_DISCLOSURE"
  | "BIRTHDAY_NOT_FOUND"
  | "CLAIM_NOT_FOUND"
  | "PARAMS_EXCEEDED"
  | "INVALID_ISSUER_PROOF"
  | "WASM_LOAD_FAILED"
  | "WASM_OOM"
  | "WASM_NOT_INITIALIZED";

export interface DisclosedClaim {
  index: number;
  salt: string;
  name: string;
  value: string;
  raw: string;
  digest: string; // SHA-256 of disclosure (base64url, matches _sd array)
}

export interface WasmExports {
  setup_prepare(
    r1csBytes: Uint8Array,
  ): Promise<{ pk: Uint8Array; vk: Uint8Array }>;
  setup_show(
    r1csBytes: Uint8Array,
  ): Promise<{ pk: Uint8Array; vk: Uint8Array }>;

  prove_prepare(
    pk: Uint8Array,
    witness: Uint8Array,
  ): Promise<{ proof: Uint8Array; instance: Uint8Array; witness: Uint8Array }>;
  prove_show(
    pk: Uint8Array,
    witness: Uint8Array,
  ): Promise<{ proof: Uint8Array; instance: Uint8Array; witness: Uint8Array }>;

  reblind(
    pk: Uint8Array,
    instance: Uint8Array,
    witness: Uint8Array,
    blinds: Uint8Array,
  ): Promise<{ proof: Uint8Array; instance: Uint8Array; witness: Uint8Array }>;

  verify(
    proof: Uint8Array,
    vk: Uint8Array,
  ): Promise<{ valid: boolean; publicValues: bigint[] }>;

  generate_shared_blinds(count: number): Promise<Uint8Array>;

  generate_witness(
    inputsJson: string,
    circuitWasm: Uint8Array,
  ): Promise<Uint8Array>;
}

export interface JwtCircuitInputs {
  sig_r: bigint;
  sig_s_inverse: bigint;
  pubKeyX: bigint;
  pubKeyY: bigint;
  message: bigint[];
  messageLength: number;
  periodIndex: number;
  matchesCount: number;
  matchSubstring: bigint[][];
  matchLength: number[];
  matchIndex: number[];
  claims: bigint[][];
  claimLengths: bigint[];
  decodeFlags: number[];
  claimFormats: bigint[];
}

export interface ShowCircuitInputs {
  deviceKeyX: bigint;
  deviceKeyY: bigint;
  sig_r: bigint;
  sig_s_inverse: bigint;
  messageHash: bigint;
  predicateLen: bigint;
  claimValues: bigint[];
  /** Attribute identity per claim slot, H(name). Shared with Prepare via comm_W_shared. */
  claimIdentifierHashes: bigint[];
  predicateClaimRefs: bigint[];
  predicateOps: bigint[];
  predicateRhsIsRef: bigint[];
  predicateRhsValues: bigint[];
  /** Public: LHS attribute name bytes per predicate; the circuit hashes them. */
  predicateClaimNames: bigint[][];
  predicateClaimNameLens: bigint[];
  /** Public: RHS attribute name bytes per predicate (claim-to-claim compareTo). */
  predicateRhsClaimNames: bigint[][];
  predicateRhsClaimNameLens: bigint[];
  tokenTypes: bigint[];
  tokenValues: bigint[];
  exprLen: bigint;
  /** Issuer hiding: key shared with Prepare via comm_W_shared, plus its registry proof. */
  issuerKeyX: bigint;
  issuerKeyY: bigint;
  issuerTreeDepth: bigint;
  issuerTreeIndex: bigint;
  issuerTreeSiblings: bigint[][];
}

export interface PrecomputeRequest {
  jwt: string;
  disclosures: string[];
  issuerPublicKey: IssuerPublicKey;
  keys: KeySet;

  /** Predicates the holder wants to prove. Drives format inference and vcSize selection. */
  predicates: import("./predicates.js").PredicateExpression;

  /** Trusted clock / profile policy for JWT validity checks. */
  profile?: import("./credential.js").CredentialProfileOptions;
}

export interface SerializedCredential {
  jwt: string;
  disclosures: string[];
  deviceBindingKey: EcdsaPublicKey;
}

export interface PrecomputedCredential {
  prepareProof: Uint8Array;
  prepareInstance: Uint8Array;
  prepareWitness: Uint8Array;
  credential: SerializedCredential;
  birthdayClaimIndex: number;
  birthdayClaim: string;
  deviceKey: EcdsaPublicKey;
  /** The issuer key the credential was verified against. Never leaves the holder. */
  issuerPublicKey: EcdsaPublicKey;
  /**
   * Normalized claim values extracted from the JWT circuit witness. Required
   * input to the Show circuit's predicate evaluation. Consumers that use the
   * typed predicate DSL never need to read this; `present()` consumes it
   * internally. Exposed so cached credentials survive serialize/deserialize.
   */
  normalizedClaimValues: bigint[];
  /**
   * Per-slot attribute identities H(name), read from the Prepare witness. Carried
   * into the Show witness so predicate slots bind to attribute names (Items 1+3).
   * The SDK never computes these (no off-circuit hashing).
   */
  claimIdentifierHashes: bigint[];
  /**
   * The per-claim decode flags and formats the JWT circuit ran under when
   * `normalizedClaimValues` was produced. `present()` compares these against
   * the formats its own predicates compile to and refuses to reuse values that
   * were normalized differently.
   */
  claimNormalization: ClaimNormalization;
  timing: PrecomputeTiming;
  /**
   * SENSITIVE — exports the bearer credential. The serialized form contains the
   * raw JWT, every unblinded disclosure, the Prepare witness, and the normalized
   * claim values — i.e. everything the ZK layer exists NOT to reveal. Anyone who
   * obtains it can impersonate the holder. Persist only in secure, holder-owned
   * storage (never a log, cache, or transport a third party can read), and treat
   * it like the credential itself. Not a presentation — presentations are the
   * output of `present()`. (Item 19: renamed intent flagged here to avoid a
   * breaking API change; prefer a hardware-backed/keychain store.)
   */
  serialize(): Uint8Array;
  /** SENSITIVE — same contents as {@link serialize}; see its warning. */
  toJSON(): SerializedPrecomputedCredentialJSON;
}

/**
 * Per-claim normalization metadata, indexed by claim slot.
 *
 * `decodeFlags[i]` is 1 when slot i was decoded and normalized, 0 when it was
 * skipped (a skipped slot normalizes to 0, which is not the claim's value).
 * `claimFormats[i]` is the circuit format code the value was normalized under
 * (0=bool, 1=uint, 2=iso_date, 3=roc_date, 4=string) and is only meaningful
 * when `decodeFlags[i]` is 1.
 */
export interface ClaimNormalization {
  decodeFlags: number[];
  claimFormats: number[];
}

export interface PrecomputeTiming {
  parseCredentialMs: number;
  buildInputsMs: number;
  prepareWitnessMs: number;
  prepareProveMs: number;
  totalMs: number;
}

export interface SerializedPrecomputedCredentialJSON {
  version: string;
  prepareProof: string;
  prepareInstance: string;
  prepareWitness: string;
  credential: SerializedCredential;
  birthdayClaimIndex: number;
  birthdayClaim: string;
  deviceKey: EcdsaPublicKey;
  issuerPublicKey: EcdsaPublicKey;
  normalizedClaimValues: string[]; // bigints serialized as decimal strings
  claimIdentifierHashes?: string[]; // bigints serialized as decimal strings
  claimNormalization: ClaimNormalization;
}

export interface PresentRequest {
  precomputed: PrecomputedCredential;
  verifierNonce: string;
  devicePrivateKey: EcdsaPrivateKey;
  keys: KeySet;

  /** Predicates to evaluate against the precomputed credential. */
  predicates: import("./predicates.js").PredicateExpression;

  /**
   * Membership proof of the credential's issuer in the issuer registry, against
   * a root the verifier accepts. See `createIssuerRegistry`.
   */
  issuerProof: import("./issuer-hiding.js").IssuerProof;

  /** Trusted clock / profile policy for JWT validity checks (re-checked at present time). */
  profile?: import("./credential.js").CredentialProfileOptions;
}

export interface PresentationProof {
  prepareProof: Uint8Array;
  prepareInstance: Uint8Array;
  showProof: Uint8Array;
  showInstance: Uint8Array;
  publicValues: ProofPublicValues;
  timing: PresentationTiming;
  serialize(): Uint8Array;
  toBase64(): string;
  toJSON(): SerializedProofJSON;
}

export interface PresentationTiming {
  showWitnessMs: number;
  showProveMs: number;
  presentMs: number;
  totalMs: number;
}

use bellpepper_core::SynthesisError;
use ff::PrimeField;
use num_bigint::{BigInt, Sign};
use serde_json::Value;
use std::{collections::HashMap, ops::Range, str::FromStr};

use crate::{circuit_size::CircuitSize, Scalar};

#[derive(Clone, Copy)]
pub enum FieldParser {
    BigIntScalar,
    U64Scalar,
    BigIntArray,
    U64Array,
    BigInt2DArray,
}

pub fn parse_inputs(
    json_value: &Value,
    field_defs: &[(&str, FieldParser)],
) -> Result<HashMap<String, Vec<BigInt>>, SynthesisError> {
    let mut inputs = HashMap::new();

    for (field_name, parser) in field_defs {
        let value = match parser {
            FieldParser::BigIntScalar => {
                vec![parse_bigint_scalar(json_value, field_name)
                    .map_err(|_| SynthesisError::AssignmentMissing)?]
            }
            FieldParser::U64Scalar => {
                vec![parse_u64_scalar(json_value, field_name)
                    .map_err(|_| SynthesisError::AssignmentMissing)?]
            }
            FieldParser::BigIntArray => parse_bigint_string_array(json_value, field_name)
                .map_err(|_| SynthesisError::AssignmentMissing)?,
            FieldParser::U64Array => parse_u64_array(json_value, field_name)
                .map_err(|_| SynthesisError::AssignmentMissing)?,
            FieldParser::BigInt2DArray => parse_2d_bigint_array(json_value, field_name)
                .map_err(|_| SynthesisError::AssignmentMissing)?,
        };
        inputs.insert(field_name.to_string(), value);
    }

    Ok(inputs)
}

// Circuit-specific input parsers
/// Parse JWT circuit inputs from JSON.
///
/// Matches the current `JWT(...)` template in `circom/circuits/jwt.circom`:
/// `claimFormats[]` is required, `ageClaimIndex` was removed when
/// the circuit switched to per-slot claim normalization.
pub fn parse_jwt_inputs(
    json_value: &Value,
) -> Result<HashMap<String, Vec<BigInt>>, SynthesisError> {
    let field_defs: &[(&str, FieldParser)] = &[
        // BigInt scalar fields (wrapped in vec)
        ("sig_r", FieldParser::BigIntScalar),
        ("sig_s_inverse", FieldParser::BigIntScalar),
        ("pubKeyX", FieldParser::BigIntScalar),
        ("pubKeyY", FieldParser::BigIntScalar),
        // U64 scalar fields (wrapped in vec)
        ("messageLength", FieldParser::U64Scalar),
        ("periodIndex", FieldParser::U64Scalar),
        ("matchesCount", FieldParser::U64Scalar),
        ("revocationValueIndex", FieldParser::U64Scalar),
        // Array fields
        ("message", FieldParser::BigIntArray),
        ("matchIndex", FieldParser::U64Array),
        ("matchLength", FieldParser::U64Array),
        ("claimLengths", FieldParser::BigIntArray),
        ("decodeFlags", FieldParser::U64Array),
        ("claimFormats", FieldParser::BigIntArray),
        // 2D array fields (flattened)
        ("matchSubstring", FieldParser::BigInt2DArray),
        ("claims", FieldParser::BigInt2DArray),
    ];

    parse_inputs(json_value, field_defs)
}

/// Parse Show circuit inputs from JSON.
///
/// Matches the current
/// `Show(nClaims, maxPredicates, maxLogicTokens, valueBits, revocationMaxDepth)`
/// template. The revocation inputs are parsed when present (`show`) and absent
/// for `show_mdoc`. Predicates + an RPN logic expression replaced the old
/// `claim/currentYear/currentMonth/currentDay` interface.
///
/// Predicate RHS encoding uses a single `predicateRhsValues[]` array:
/// - when `predicateRhsIsRef[i] = 0`, `predicateRhsValues[i]` is a literal value
/// - when `predicateRhsIsRef[i] = 1`, `predicateRhsValues[i]` is a claim index
///
/// This supports both attribute-to-literal and attribute-to-attribute comparisons.
pub fn parse_show_inputs(
    json_value: &Value,
) -> Result<HashMap<String, Vec<BigInt>>, SynthesisError> {
    let field_defs: &[(&str, FieldParser)] = &[
        // BigInt scalar fields (wrapped in vec)
        ("deviceKeyX", FieldParser::BigIntScalar),
        ("deviceKeyY", FieldParser::BigIntScalar),
        ("sig_r", FieldParser::BigIntScalar),
        ("sig_s_inverse", FieldParser::BigIntScalar),
        ("messageHash", FieldParser::BigIntScalar),
        ("predicateLen", FieldParser::BigIntScalar),
        ("exprLen", FieldParser::BigIntScalar),
        // Array fields
        ("claimValues", FieldParser::BigIntArray),
        // Attribute identity per claim slot, shared with the credential circuit.
        // The verifier-supplied attribute NAME bytes (public) are hashed in-circuit
        // to the required identity, so a predicate cannot be re-aimed at a different
        // attribute (Items 1+3). Names are 2D [maxPredicates][NAME_ID_LEN].
        ("claimIdentifierHashes", FieldParser::BigIntArray),
        ("predicateClaimRefs", FieldParser::BigIntArray),
        ("predicateOps", FieldParser::BigIntArray),
        ("predicateRhsIsRef", FieldParser::BigIntArray),
        ("predicateRhsValues", FieldParser::BigIntArray),
        ("predicateClaimNames", FieldParser::BigInt2DArray),
        ("predicateClaimNameLens", FieldParser::BigIntArray),
        ("predicateRhsClaimNames", FieldParser::BigInt2DArray),
        ("predicateRhsClaimNameLens", FieldParser::BigIntArray),
        ("tokenTypes", FieldParser::BigIntArray),
        ("tokenValues", FieldParser::BigIntArray),
        // Issuer hiding: key shared from Prepare, plus its LeanIMT membership proof.
        ("issuerKeyX", FieldParser::BigIntScalar),
        ("issuerKeyY", FieldParser::BigIntScalar),
        ("issuerTreeDepth", FieldParser::BigIntScalar),
        ("issuerTreeIndex", FieldParser::BigIntScalar),
        ("issuerTreeSiblings", FieldParser::BigInt2DArray),
    ];
    let revocation_defs: &[(&str, FieldParser)] = &[
        ("revocationValue", FieldParser::BigIntArray),
        ("revocationLeafValue", FieldParser::BigIntArray),
        ("revocationLeafNextValue", FieldParser::BigIntArray),
        ("revocationLeafIndex", FieldParser::BigIntScalar),
        ("revocationDepth", FieldParser::BigIntScalar),
        ("revocationSiblings", FieldParser::BigInt2DArray),
    ];

    let mut inputs = parse_inputs(json_value, field_defs)?;
    if json_value.get("revocationValue").is_some() {
        inputs.extend(parse_inputs(json_value, revocation_defs)?);
    }
    Ok(inputs)
}

/// Convert a single BigInt to Scalar
pub fn bigint_to_scalar(bigint_val: BigInt) -> Result<Scalar, SynthesisError> {
    let bytes = bigint_val.to_bytes_le().1;

    // Validate size before padding
    if bytes.len() > 32 {
        return Err(SynthesisError::Unsatisfiable);
    }

    let mut padded = [0u8; 32];
    padded[..bytes.len()].copy_from_slice(&bytes);

    Scalar::from_bytes(&padded)
        .into_option()
        .ok_or(SynthesisError::Unsatisfiable)
}

pub fn convert_bigint_to_scalar(
    bigint_witness: Vec<BigInt>,
) -> Result<Vec<Scalar>, SynthesisError> {
    bigint_witness.into_iter().map(bigint_to_scalar).collect()
}

/// Parses the Circom witness binary format (.wtns) directly to Scalar vector
pub fn parse_witness(witness_bytes: &[u8]) -> Result<Vec<Scalar>, SynthesisError> {
    let mut pos = 0;

    // Validate .wtns header (4 bytes magic)
    if witness_bytes.len() < 12 || &witness_bytes[0..4] != b"wtns" {
        return Err(SynthesisError::Unsatisfiable);
    }
    pos += 4;

    // Skip version (4 bytes)
    pos += 4;

    // Read number of sections (4 bytes)
    let n_sections = u32::from_le_bytes(witness_bytes[pos..pos + 4].try_into().unwrap());
    pos += 4;

    // Number of bytes per field element (from section 1)
    let mut n8 = 0;

    // Iterate through sections to find witness data (section_id = 2)
    for _ in 0..n_sections {
        if pos + 12 > witness_bytes.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        let section_id = u32::from_le_bytes(witness_bytes[pos..pos + 4].try_into().unwrap());
        pos += 4;

        let section_length =
            u64::from_le_bytes(witness_bytes[pos..pos + 8].try_into().unwrap()) as usize;
        pos += 8;

        match section_id {
            // Section 1: Header metadata
            // Contains n8 (4 bytes), field q (32 bytes), n_witness_values (4 bytes)
            1 => {
                if pos + 4 > witness_bytes.len() {
                    return Err(SynthesisError::Unsatisfiable);
                }
                n8 = u32::from_le_bytes(witness_bytes[pos..pos + 4].try_into().unwrap()) as usize;
                pos += section_length; // Skip entire section
            }

            // Section 2: Witness data
            // Contains witness elements (n8 bytes each)
            2 => {
                if n8 == 0 {
                    return Err(SynthesisError::Unsatisfiable);
                }

                if pos + section_length > witness_bytes.len() {
                    return Err(SynthesisError::Unsatisfiable);
                }

                // Parse witness elements directly to Scalar
                let witness_data = &witness_bytes[pos..pos + section_length];
                let num_elements = section_length / n8;

                let mut scalars = Vec::with_capacity(num_elements);

                for chunk in witness_data.chunks(n8) {
                    // Pad to 32 bytes if needed (n8 might be less than 32)
                    let mut padded = [0u8; 32];
                    padded[..chunk.len()].copy_from_slice(chunk);

                    // Convert to Scalar
                    let scalar = Scalar::from_bytes(&padded)
                        .into_option()
                        .ok_or(SynthesisError::Unsatisfiable)?;
                    scalars.push(scalar);
                }

                return Ok(scalars);
            }

            // Skip any other section
            _ => {
                pos += section_length;
            }
        }
    }

    Err(SynthesisError::Unsatisfiable)
}

/// Convert HashMap<String, Vec<BigInt>> to JSON string for witnesscalc_adapter.
/// Reconstructs 2D arrays for fields that were flattened during parsing.
pub fn hashmap_to_json_string(
    inputs: &HashMap<String, Vec<BigInt>>,
    max_matches: usize,
    max_substring_length: usize,
    max_claims_length: usize,
) -> Result<String, SynthesisError> {
    use serde_json::json;

    let mut json_map = serde_json::Map::new();

    // Define 2D array fields and their dimensions (rows, cols).
    // `claims` is sized `maxClaims = maxMatches - 2` because the first two
    // match slots are reserved for the device-binding key extraction.
    let max_claims = max_matches.saturating_sub(2);
    let two_d_fields: HashMap<&str, (usize, usize)> = [
        ("claims", (max_claims, max_claims_length)),
        ("matchSubstring", (max_matches, max_substring_length)),
    ]
    .iter()
    .cloned()
    .collect();

    for (key, values) in inputs.iter() {
        // Check if this is a 2D array field
        if let Some(&(rows, cols)) = two_d_fields.get(key.as_str()) {
            // Reconstruct 2D array from flattened 1D array
            let mut array_2d = Vec::with_capacity(rows);
            for i in 0..rows {
                let start = i * cols;
                let end = start + cols;
                if end <= values.len() {
                    let row: Vec<String> = values[start..end]
                        .iter()
                        .map(|bigint| bigint.to_string())
                        .collect();
                    array_2d.push(json!(row));
                } else {
                    return Err(SynthesisError::Unsatisfiable);
                }
            }
            json_map.insert(key.clone(), json!(array_2d));
        } else {
            // Regular 1D array
            let string_array: Vec<String> =
                values.iter().map(|bigint| bigint.to_string()).collect();
            json_map.insert(key.clone(), json!(string_array));
        }
    }

    serde_json::to_string(&json_map).map_err(|_| SynthesisError::Unsatisfiable)
}

pub fn parse_byte(value: &Value) -> Result<u8, SynthesisError> {
    if let Some(as_str) = value.as_str() {
        let parsed = as_str
            .parse::<u16>()
            .map_err(|_| SynthesisError::AssignmentMissing)?;
        return u8::try_from(parsed).map_err(|_| SynthesisError::AssignmentMissing);
    }

    if let Some(as_u64) = value.as_u64() {
        return u8::try_from(as_u64).map_err(|_| SynthesisError::AssignmentMissing);
    }

    Err(SynthesisError::AssignmentMissing)
}

// JSON Parsing Helpers
/// Parse a single BigInt from a string field
fn parse_bigint_scalar(json: &Value, key: &str) -> Result<BigInt, String> {
    let s = json
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or("Field must be a string")?;
    BigInt::from_str(s).map_err(|_| "Failed to parse as BigInt".to_string())
}

/// Parse a single u64 from a number field and convert to BigInt
fn parse_u64_scalar(json: &Value, key: &str) -> Result<BigInt, String> {
    json.get(key)
        .and_then(|v| v.as_u64())
        .map(BigInt::from)
        .ok_or("Field must be a number".to_string())
}

/// Parse an array of BigInt strings
fn parse_bigint_string_array(json: &Value, key: &str) -> Result<Vec<BigInt>, String> {
    let array = json
        .get(key)
        .and_then(|v| v.as_array())
        .ok_or("Field must be an array")?;

    array
        .iter()
        .map(|v| {
            let s = v.as_str().ok_or("Array element must be a string")?;
            BigInt::from_str(s).map_err(|_| "Failed to parse array element as BigInt".to_string())
        })
        .collect()
}

/// Parse an array of u64 numbers and convert to BigInt
fn parse_u64_array(json: &Value, key: &str) -> Result<Vec<BigInt>, String> {
    json.get(key)
        .and_then(|v| v.as_array())
        .ok_or("Field must be an array")?
        .iter()
        .map(|v| {
            v.as_u64()
                .map(BigInt::from)
                .ok_or("Array element must be a number".to_string())
        })
        .collect()
}

/// Parse a 2D array of BigInt strings and flatten into 1D vector
fn parse_2d_bigint_array(json: &Value, key: &str) -> Result<Vec<BigInt>, String> {
    let outer_array = json
        .get(key)
        .and_then(|v| v.as_array())
        .ok_or("Field must be an array")?;

    // Pre-calculate total capacity
    let total_capacity: usize = outer_array
        .iter()
        .filter_map(|v| v.as_array())
        .map(|arr| arr.len())
        .sum();

    let mut result = Vec::with_capacity(total_capacity);

    for inner_value in outer_array.iter() {
        let inner_array = inner_value
            .as_array()
            .ok_or("Outer array element must be an array")?;

        for v in inner_array.iter() {
            let s = v.as_str().ok_or("Inner array element must be a string")?;
            let bigint =
                BigInt::from_str(s).map_err(|_| "Failed to parse inner array element as BigInt")?;
            result.push(bigint);
        }
    }

    Ok(result)
}

/// Layout of the JWT (Prepare) circuit's public outputs within the witness vector.
///
/// Circom lays public IO out as outputs first, then public inputs (in template
/// declaration order), so for the JWT circuit:
/// 1. `normalizedClaimValues[n_claims]` where `n_claims = maxMatches - 2`
/// 2. `KeyBindingX`
/// 3. `KeyBindingY`
/// 4. `decodeFlags[n_claims]`, `claimFormats[n_claims]`, which say how each
///    entry of `normalizedClaimValues` was produced
///
/// all declared public in `circom/circuits/main/jwt*.circom`.
///
/// The circuit has no public *outputs*: claim values would reveal the attribute,
/// the device key would link every presentation and the issuer key would reveal
/// the issuer, so all three travel privately via `comm_W_shared`:
///   witness[1..1+n]    = main.decodeFlags[..]
///   witness[1+n..1+2n] = main.claimFormats[..]
/// with pubKeyX/Y at `CircuitSize::issuer_key_witness_start` and
/// normalizedClaimValues and KeyBindingX/Y at `CircuitSize::claim_values_witness_start`.
///
/// Offsets re-derived by `tests/witness_layout.rs`.
#[derive(Debug, Clone, Copy)]
pub struct JwtOutputLayout {
    /// Witness index of `normalizedClaimValues[0]`. Private and size-dependent —
    /// see [`CircuitSize::claim_values_witness_start`].
    pub claim_values_start: usize,
    /// Number of normalized claim values, equal to `maxMatches - 2`.
    pub claim_values_len: usize,
    /// Witness index of `claimIdentifierHashes[0]` (H(name) per slot). Follows the
    /// claim values (with name-extractor internals in between) and precedes the
    /// device key. Bound into `comm_W_shared` so predicate slots carry attribute identity.
    pub claim_identifier_hashes_start: usize,
    pub keybinding_x_index: usize,
    pub keybinding_y_index: usize,
    /// Witness index of `RevocationValue[0]` (hi limb); the lo limb follows.
    pub revocation_value_index: usize,
    /// Witness index of the private issuer key coordinate `pubKeyX` (shared).
    pub issuer_key_x_index: usize,
    /// Witness index of the private issuer key coordinate `pubKeyY` (shared).
    pub issuer_key_y_index: usize,
    /// Witness index of `decodeFlags[0]`. The array is `claim_values_len` long.
    pub decode_flags_start: usize,
    /// Witness index of `claimFormats[0]`. The array is `claim_values_len` long.
    pub claim_formats_start: usize,
}

impl JwtOutputLayout {
    pub fn claim_values_range(&self) -> Range<usize> {
        self.claim_values_start..self.claim_values_start + self.claim_values_len
    }

    pub fn claim_identifier_hashes_range(&self) -> Range<usize> {
        self.claim_identifier_hashes_start
            ..self.claim_identifier_hashes_start + self.claim_values_len
    }

    pub fn decode_flags_range(&self) -> Range<usize> {
        self.decode_flags_start..self.decode_flags_start + self.claim_values_len
    }

    pub fn claim_formats_range(&self) -> Range<usize> {
        self.claim_formats_start..self.claim_formats_start + self.claim_values_len
    }

    /// Public IO: decodeFlags + claimFormats.
    ///
    /// Claim values, the device key and the issuer key are deliberately absent
    /// and travel privately via `comm_W_shared`.
    pub fn num_public(&self) -> usize {
        2 * self.claim_values_len
    }

    /// Witness indices the shared partition must equal, in the order
    /// `PrepareCircuit::shared` pushes them (see [`SHARED_LAYOUT`]).
    pub fn shared_witness_indices(&self) -> Vec<usize> {
        let mut idx = vec![self.keybinding_x_index, self.keybinding_y_index];
        idx.extend(self.claim_values_range());
        idx.extend(self.claim_identifier_hashes_range());
        idx.extend([self.issuer_key_x_index, self.issuer_key_y_index]);
        idx.extend([
            self.revocation_value_index,
            self.revocation_value_index + 1,
        ]);
        idx
    }
}

/// Calculate JWT circuit witness layout for a compiled circuit size.
pub fn calculate_jwt_output_indices(size: CircuitSize) -> JwtOutputLayout {
    let claim_values_start = size.claim_values_witness_start();
    let claim_values_len = size.n_claims();
    // `jwt.circom` assigns claim values, then (after name-extractor internals)
    // claimIdentifierHashes[maxClaims], then KeyBindingX/Y. The key is NO LONGER
    // contiguous with the claim values.
    let claim_identifier_hashes_start = size.claim_identifier_hashes_witness_start();
    let keybinding_x_index = claim_identifier_hashes_start + claim_values_len;
    let keybinding_y_index = keybinding_x_index + 1;
    // Declared right after KeyBindingY in jwt.circom.
    let revocation_value_index = keybinding_y_index + 1;
    let issuer_key_x_index = size.issuer_key_witness_start();
    let issuer_key_y_index = issuer_key_x_index + 1;
    // No public outputs, so the public inputs occupy witness[1..] directly.
    let decode_flags_start = 1;
    let claim_formats_start = decode_flags_start + claim_values_len;

    JwtOutputLayout {
        claim_values_start,
        claim_values_len,
        claim_identifier_hashes_start,
        keybinding_x_index,
        keybinding_y_index,
        revocation_value_index,
        issuer_key_x_index,
        issuer_key_y_index,
        decode_flags_start,
        claim_formats_start,
    }
}

/// Order of the shared witness segment, identical in Prepare/MDOC and Show:
/// `[KeyBindingX, KeyBindingY, claimValues.., claimIdentifierHashes.., issuerKeyX, issuerKeyY,
///   RevocationValue[0], RevocationValue[1]]`. The revocation value is
/// present only in the JWT flow (`show`); MDOC pairs with `show_mdoc`, which has none.
pub const SHARED_LAYOUT: &str = "KeyBindingX, KeyBindingY, claimValues.., claimIdentifierHashes.., \
     issuerKeyX, issuerKeyY, RevocationValue[0..2] (JWT only)";

/// Recombine a `[hi, lo]` pair of 128-bit limbs from a Show proof's public values,
/// starting at witness index `witness_index`, into the 256-bit root (`hi * 2^128 + lo`).
fn root_from_show_public_values(
    public_values: &[Scalar],
    witness_index: usize,
    what: &str,
) -> Result<BigInt, String> {
    let limb = |i: usize| -> Result<BigInt, String> {
        let v = public_values
            .get(i)
            .ok_or_else(|| format!("show proof exposes {} public values", public_values.len()))?;
        let limb = BigInt::from_bytes_le(Sign::Plus, v.to_repr().as_ref());
        if limb.bits() > 128 {
            return Err(format!("{what} limb exceeds 128 bits"));
        }
        Ok(limb)
    };
    // public_values[i] is witness[i + 1].
    let hi = limb(witness_index - 1)?;
    let lo = limb(witness_index)?;
    Ok((hi << 128) + lo)
}

/// Recombine the Show proof's `issuerRoot[hi, lo]` limbs into the 256-bit
/// issuer registry root (`hi * 2^128 + lo`), as stored on chain.
pub fn issuer_root_from_show_public_values(public_values: &[Scalar]) -> Result<BigInt, String> {
    root_from_show_public_values(public_values, SHOW_ISSUER_ROOT_INDEX, "issuer root")
}

/// Recombine the `show` proof's `revocationRoot[hi, lo]` limbs into the 256-bit
/// revocation registry root (`0` for an empty registry).
pub fn revocation_root_from_show_public_values(public_values: &[Scalar]) -> Result<BigInt, String> {
    root_from_show_public_values(public_values, SHOW_REVOCATION_ROOT_INDEX, "revocation root")
}

/// Show circuit template parameters
/// (`Show(nClaims, maxPredicates, maxLogicTokens, valueBits, maxIssuerDepth, revocationMaxDepth)`),
/// fixed across all VC sizes (see `circom/circuits.json`): `show` is
/// `Show(2, 2, 8, 64, 8, 10)` and `show_mdoc` is `Show(2, 2, 8, 64, 8, 0)`. `nClaims`
/// is always `2` because every JWT size uses `maxMatches = 4`.
pub const SHOW_MAX_PREDICATES: usize = 2;
pub const SHOW_MAX_LOGIC_TOKENS: usize = 8;
/// Fixed byte width an attribute name is hashed over (Show NAME_ID_LEN in show.circom).
pub const SHOW_NAME_ID_LEN: usize = 31;
/// Max issuer registry depth (Show `maxIssuerDepth`), at most 2^8 issuers.
pub const SHOW_MAX_ISSUER_DEPTH: usize = 8;
/// Max LeanIMT+ depth of the revocation tree in the `show` circuit.
pub const SHOW_REVOCATION_MAX_DEPTH: usize = 10;
/// Witness index of `issuerRoot[0]` (hi limb); `issuerRoot[1]` (lo) follows.
pub const SHOW_ISSUER_ROOT_INDEX: usize = 2;
/// Witness index of `revocationRoot[0]` (hi limb) in `show`; `revocationRoot[1]` follows.
pub const SHOW_REVOCATION_ROOT_INDEX: usize = 4;

/// Number of public inputs of the Show circuit: the verifier statement
/// (messageHash + predicate program), in declaration order:
///   messageHash, predicateLen,
///   predicateClaimRefs[maxPredicates], predicateOps[maxPredicates],
///   predicateRhsIsRef[maxPredicates], predicateRhsValues[maxPredicates],
///   predicateClaimNames[maxPredicates][NAME_ID_LEN], predicateClaimNameLens[maxPredicates],
///   predicateRhsClaimNames[maxPredicates][NAME_ID_LEN], predicateRhsClaimNameLens[maxPredicates],
///   tokenTypes[maxLogicTokens], tokenValues[maxLogicTokens], exprLen
///
/// The attribute names are public so the verifier sees (and pins) which attribute
/// each predicate operand was bound to; the circuit hashes them to the identity.
pub const SHOW_STATEMENT_LEN: usize = 3
    + 6 * SHOW_MAX_PREDICATES
    + 2 * SHOW_MAX_PREDICATES * SHOW_NAME_ID_LEN
    + 2 * SHOW_MAX_LOGIC_TOKENS;

/// Number of public IO signals of the `show` circuit (with revocation):
/// `expressionResult`, `issuerRoot[2]`, `revocationRoot[2]`, then the verifier
/// statement (5 + 155 = 160).
pub const SHOW_NUM_PUBLIC: usize = 5 + SHOW_STATEMENT_LEN;

/// Which compiled Show circuit to use. The SD-JWT flow proves revocation
/// (`show`); the MDOC flow has no revocation value (`show_mdoc`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ShowVariant {
    #[default]
    Jwt,
    Mdoc,
}

impl ShowVariant {
    pub fn circuit_name(self) -> &'static str {
        match self {
            ShowVariant::Jwt => "show",
            ShowVariant::Mdoc => "show_mdoc",
        }
    }

    pub fn has_revocation(self) -> bool {
        self == ShowVariant::Jwt
    }

    /// Public outputs: `expressionResult` and `issuerRoot[2]`, plus
    /// `revocationRoot[2]` with revocation.
    pub fn num_outputs(self) -> usize {
        if self.has_revocation() {
            5
        } else {
            3
        }
    }

    pub fn num_public(self) -> usize {
        self.num_outputs() + SHOW_STATEMENT_LEN
    }
}

/// Layout of the Show circuit's witness vector.
///
/// Verified against `build/show/show.sym` and `build/show_mdoc/show_mdoc.sym`:
///   witness[1]                  = main.expressionResult (public output)
///   witness[2..=3]              = main.issuerRoot[hi, lo] (public output)
///   witness[4..=5]              = main.revocationRoot[hi, lo] (public output, `show` only)
///   witness[..=num_public]      = messageHash + predicate program (public inputs)
///   then private: deviceKeyX, deviceKeyY, sig_r, sig_s_inverse,
///   claimValues[n], claimIdentifierHashes[n], issuerKeyX, issuerKeyY,
///   issuerTreeDepth, issuerTreeIndex, revocationValue[2] (`show` only).
/// The tree siblings are linear in the constraints, so the optimizer substitutes
/// them out of the witness and the revocation value directly follows
/// `issuerTreeIndex`.
#[derive(Debug, Clone, Copy)]
pub struct ShowWitnessLayout {
    pub variant: ShowVariant,
    pub expression_result_index: usize,
    pub device_key_x_index: usize,
    pub device_key_y_index: usize,
    pub claim_values_start: usize,
    pub claim_values_len: usize,
    pub claim_identifier_hashes_start: usize,
    pub issuer_key_x_index: usize,
    /// Witness index of `revocationValue[0]`; `None` without revocation.
    pub revocation_value_index: Option<usize>,
}

impl ShowWitnessLayout {
    pub fn claim_values_range(&self) -> Range<usize> {
        self.claim_values_start..self.claim_values_start + self.claim_values_len
    }

    pub fn claim_identifier_hashes_range(&self) -> Range<usize> {
        self.claim_identifier_hashes_start
            ..self.claim_identifier_hashes_start + self.claim_values_len
    }

    pub fn num_public(&self) -> usize {
        self.variant.num_public()
    }

    /// Witness indices the shared partition must equal (see [`SHARED_LAYOUT`]).
    pub fn shared_witness_indices(&self) -> Vec<usize> {
        let mut idx = vec![self.device_key_x_index, self.device_key_y_index];
        idx.extend(self.claim_values_range());
        idx.extend(self.claim_identifier_hashes_range());
        idx.extend([self.issuer_key_x_index, self.issuer_key_x_index + 1]);
        if let Some(i) = self.revocation_value_index {
            idx.extend([i, i + 1]);
        }
        idx
    }
}

/// Calculate the Show witness layout for `n_claims` (the JWT circuit's
/// `maxMatches - 2`, see [`CircuitSize::n_claims`]) and the circuit variant.
pub fn calculate_show_witness_indices(n_claims: usize, variant: ShowVariant) -> ShowWitnessLayout {
    // Private signals follow the public prefix: deviceKeyX, deviceKeyY, sig_r,
    // sig_s_inverse, claimValues[..], claimIdentifierHashes[..], issuerKeyX,
    // issuerKeyY, issuerTreeDepth, issuerTreeIndex, then the revocation inputs.
    let device_key_x_index = variant.num_public() + 1;
    let claim_values_start = device_key_x_index + 4;
    let claim_identifier_hashes_start = claim_values_start + n_claims;
    let issuer_key_x_index = claim_identifier_hashes_start + n_claims;
    ShowWitnessLayout {
        variant,
        expression_result_index: 1,
        device_key_x_index,
        device_key_y_index: device_key_x_index + 1,
        claim_values_start,
        claim_values_len: n_claims,
        claim_identifier_hashes_start,
        issuer_key_x_index,
        revocation_value_index: variant
            .has_revocation()
            .then_some(issuer_key_x_index + 4),
    }
}

/// Layout of the MDOC circuit's public outputs within the witness vector.
///
/// Circom lays public IO out as outputs first, then public inputs (in template
/// declaration order), so for the MDOC circuit the public prefix is:
/// 1. `validUntilDate`, the only output
/// 2. `valueTypes[maxClaims]`, `claimFlags[maxClaims]`, which say how each entry
///    of `normalizedClaimValues` was produced
///
/// declared public in `circom/circuits/main/mdoc.circom`. `normalizedClaimValues`,
/// `deviceKeyX`/`deviceKeyY` and the issuer `pubKeyX`/`pubKeyY` are private and reach Show through the shared
/// witness segment; their indices are hardcoded constants below because nothing
/// about the public prefix implies them.
#[derive(Debug, Clone, Copy)]
pub struct MdocOutputLayout {
    pub valid_until_index: usize,
    pub claim_values_start: usize,
    pub claim_values_len: usize,
    pub claim_identifier_hashes_start: usize,
    pub device_key_x_index: usize,
    pub device_key_y_index: usize,
    /// Witness index of the private issuer key coordinate `pubKeyX` (shared).
    pub issuer_key_x_index: usize,
    /// Witness index of the private issuer key coordinate `pubKeyY` (shared).
    pub issuer_key_y_index: usize,
    /// Witness index of `valueTypes[0]`. The array is `claim_values_len` long.
    pub value_types_start: usize,
    /// Witness index of `claimFlags[0]`. The array is `claim_values_len` long.
    pub claim_flags_start: usize,
}

impl MdocOutputLayout {
    pub fn claim_values_range(&self) -> Range<usize> {
        self.claim_values_start..self.claim_values_start + self.claim_values_len
    }

    pub fn value_types_range(&self) -> Range<usize> {
        self.value_types_start..self.value_types_start + self.claim_values_len
    }

    pub fn claim_flags_range(&self) -> Range<usize> {
        self.claim_flags_start..self.claim_flags_start + self.claim_values_len
    }

    /// Public IO: the validUntilDate output, then valueTypes + claimFlags inputs.
    /// Claim values, the device key and the issuer key are private: see
    /// [`JwtOutputLayout::num_public`].
    pub fn num_public(&self) -> usize {
        2 * self.claim_values_len + 1
    }

    /// Witness indices the shared partition must equal, in the order
    /// `MdocCircuit::shared` pushes them.
    pub fn shared_witness_indices(&self, shared_claims: usize) -> Vec<usize> {
        let mut idx = vec![self.device_key_x_index, self.device_key_y_index];
        idx.extend(self.claim_values_start..self.claim_values_start + shared_claims);
        idx.extend(
            self.claim_identifier_hashes_start
                ..self.claim_identifier_hashes_start + shared_claims,
        );
        idx.extend([self.issuer_key_x_index, self.issuer_key_y_index]);
        idx
    }
}

/// Calculate MDOC circuit witness layout from `maxClaims`.
///
/// Verified against `build/mdoc/mdoc.sym` (`MDOC(1792, 256, 4, 32, 64)`):
///   witness[1]    = main.validUntilDate  (public output)
///   witness[2]    = main.valueTypes[0]   (public input)
///   witness[1802] = main.pubKeyX         (private, shared)
///   witness[2966] = main.normalizedClaimValues[0] (private, shared)
///   witness[2970] = main.claimIdentifierHashes[0]  (private, shared)
///   witness[2974] = main.deviceKeyX      (private, shared)
pub fn calculate_mdoc_output_indices(max_claims: usize) -> MdocOutputLayout {
    let issuer_key_x_index = MDOC_ISSUER_KEY_WITNESS_START;
    let issuer_key_y_index = issuer_key_x_index + 1;
    // The lone public output occupies witness[1]; the public inputs follow.
    let value_types_start = 2;
    let claim_flags_start = value_types_start + max_claims;


    MdocOutputLayout {
        valid_until_index: 1,
        claim_values_start: MDOC_CLAIM_VALUES_WITNESS_START,
        claim_values_len: max_claims,
        claim_identifier_hashes_start: MDOC_CLAIM_IDENTIFIER_HASHES_WITNESS_START,
        device_key_x_index: MDOC_DEVICE_KEY_WITNESS_START,
        device_key_y_index: MDOC_DEVICE_KEY_WITNESS_START + 1,
        issuer_key_x_index,
        issuer_key_y_index,
        value_types_start,
        claim_flags_start,
    }
}

/// Witness index of `main.normalizedClaimValues[0]` in the compiled MDOC circuit.
/// Re-derived from `build/mdoc/mdoc.sym` by `tests/witness_layout.rs`.
pub const MDOC_CLAIM_VALUES_WITNESS_START: usize = 2966;

/// Witness index of `main.claimIdentifierHashes[0]` in the compiled MDOC circuit.
/// Re-derived from `build/mdoc/mdoc.sym` by `tests/witness_layout.rs`.
pub const MDOC_CLAIM_IDENTIFIER_HASHES_WITNESS_START: usize = 2970;

/// Witness index of `main.deviceKeyX` in the compiled MDOC circuit; `deviceKeyY`
/// follows it. Private since the unlinkability fix, so the index is no longer
/// implied by the public prefix and must be re-derived from
/// `build/mdoc/mdoc.sym` by `tests/witness_layout.rs`.
pub const MDOC_DEVICE_KEY_WITNESS_START: usize = 2974;

/// Witness index of the private issuer `main.pubKeyX`; `pubKeyY` follows.
/// Re-derived from `build/mdoc/mdoc.sym` by `tests/witness_layout.rs`.
pub const MDOC_ISSUER_KEY_WITNESS_START: usize = 1802;

/// Parse MDOC circuit inputs from JSON.
///
/// Matches `MDOC(maxCredLen, maxPreimageLen, maxClaims, maxIdentifierLen, maxValueLen)`
/// in `circom/circuits/mdoc.circom`.
pub fn parse_mdoc_inputs(
    json_value: &Value,
) -> Result<HashMap<String, Vec<BigInt>>, SynthesisError> {
    let field_defs: &[(&str, FieldParser)] = &[
        ("pubKeyX", FieldParser::BigIntScalar),
        ("pubKeyY", FieldParser::BigIntScalar),
        ("sig_r", FieldParser::BigIntScalar),
        ("sig_s_inverse", FieldParser::BigIntScalar),
        ("messageLength", FieldParser::BigIntScalar),
        ("validUntilPrefixPos", FieldParser::BigIntScalar),
        ("deviceKeyPos", FieldParser::BigIntScalar),
        ("message", FieldParser::BigIntArray),
        ("preimageLengths", FieldParser::BigIntArray),
        ("identifierLengths", FieldParser::BigIntArray),
        ("identifierPositions", FieldParser::BigIntArray),
        ("digestIds", FieldParser::BigIntArray),
        ("encodedDigestPositions", FieldParser::BigIntArray),
        ("elementValueLabelPositions", FieldParser::BigIntArray),
        ("valueStarts", FieldParser::BigIntArray),
        ("valueEnds", FieldParser::BigIntArray),
        ("valueTypes", FieldParser::BigIntArray),
        ("claimFlags", FieldParser::BigIntArray),
        ("digestInputsPaddedLen", FieldParser::BigIntArray),
        ("preimages", FieldParser::BigInt2DArray),
        ("identifierCbor", FieldParser::BigInt2DArray),
        ("digestInputsPadded", FieldParser::BigInt2DArray),
    ];

    parse_inputs(json_value, field_defs)
}

/// Convert HashMap<String, Vec<BigInt>> to JSON string for witnesscalc_adapter (MDOC).
/// Reconstructs the three MDOC 2D arrays using their declared dimensions.
pub fn mdoc_hashmap_to_json_string(
    inputs: &HashMap<String, Vec<BigInt>>,
    max_claims: usize,
    max_preimage_len: usize,
    max_identifier_len: usize,
    max_value_len: usize,
) -> Result<String, SynthesisError> {
    use serde_json::json;

    let mut json_map = serde_json::Map::new();

    let two_d_fields: HashMap<&str, (usize, usize)> = [
        ("preimages", (max_claims, max_preimage_len)),
        ("identifierCbor", (max_claims, max_identifier_len)),
        ("digestInputsPadded", (max_claims, max_value_len)),
    ]
    .iter()
    .cloned()
    .collect();

    for (key, values) in inputs.iter() {
        if let Some(&(rows, cols)) = two_d_fields.get(key.as_str()) {
            let mut array_2d = Vec::with_capacity(rows);
            for i in 0..rows {
                let start = i * cols;
                let end = start + cols;
                if end <= values.len() {
                    let row: Vec<String> = values[start..end]
                        .iter()
                        .map(|bigint| bigint.to_string())
                        .collect();
                    array_2d.push(json!(row));
                } else {
                    return Err(SynthesisError::Unsatisfiable);
                }
            }
            json_map.insert(key.clone(), json!(array_2d));
        } else {
            let string_array: Vec<String> =
                values.iter().map(|bigint| bigint.to_string()).collect();
            json_map.insert(key.clone(), json!(string_array));
        }
    }

    serde_json::to_string(&json_map).map_err(|_| SynthesisError::Unsatisfiable)
}

#[cfg(test)]
mod show_witness_indices_tests {
    use super::*;

    /// Catches witness-layout drift between the Show `.sym` files and
    /// calculate_show_witness_indices, which would silently break the
    /// Prepare<->Show commitment binding.
    #[test]
    fn witness_indices_match_show_sym() {
        for variant in [ShowVariant::Jwt, ShowVariant::Mdoc] {
            let name = variant.circuit_name();
            let sym_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(format!("../circom/build/{name}/{name}.sym"));
            if !sym_path.exists() {
                eprintln!("{} not found; skipping.", sym_path.display());
                continue;
            }

            let contents = std::fs::read_to_string(&sym_path).expect("read show sym");
            let idx_of = |signal: &str| -> Option<usize> {
                contents.lines().find_map(|line| {
                    let mut parts = line.split(',');
                    let _ = parts.next();
                    let witness_idx = parts.next()?;
                    let _ = parts.next();
                    (parts.next()?.trim() == signal)
                        .then(|| witness_idx.parse::<i64>().ok().filter(|i| *i >= 0))
                        .flatten()
                        .map(|i| i as usize)
                })
            };

            let layout = calculate_show_witness_indices(2, variant);
            let mut expected = vec![
                ("main.expressionResult", Some(layout.expression_result_index)),
                ("main.deviceKeyX", Some(layout.device_key_x_index)),
                ("main.deviceKeyY", Some(layout.device_key_y_index)),
                ("main.claimValues[0]", Some(layout.claim_values_start)),
                ("main.claimIdentifierHashes[0]", Some(layout.claim_identifier_hashes_start)),
                ("main.exprLen", Some(layout.num_public())),
                ("main.issuerRoot[0]", Some(SHOW_ISSUER_ROOT_INDEX)),
                ("main.issuerRoot[1]", Some(SHOW_ISSUER_ROOT_INDEX + 1)),
                ("main.issuerKeyX", Some(layout.issuer_key_x_index)),
                ("main.issuerKeyY", Some(layout.issuer_key_x_index + 1)),
            ];
            if let Some(i) = layout.revocation_value_index {
                expected.push(("main.revocationRoot[0]", Some(SHOW_REVOCATION_ROOT_INDEX)));
                expected.push(("main.revocationRoot[1]", Some(SHOW_REVOCATION_ROOT_INDEX + 1)));
                expected.push(("main.revocationValue[0]", Some(i)));
                expected.push(("main.revocationValue[1]", Some(i + 1)));
            }

            for (signal, index) in expected {
                assert_eq!(idx_of(signal), index, "{signal} index drifted from {name}.sym");
            }
        }
    }
}

#[cfg(test)]
mod issuer_root_tests {
    use super::*;
    use ff::Field;

    /// `[expressionResult, issuerRoot[hi, lo], revocationRoot[hi, lo]]`.
    fn show_public_values(hi: BigInt, lo: BigInt) -> Vec<Scalar> {
        let mut v = vec![Scalar::ONE];
        v.push(bigint_to_scalar(hi).unwrap());
        v.push(bigint_to_scalar(lo).unwrap());
        v.push(bigint_to_scalar(BigInt::from(7u8)).unwrap());
        v.push(bigint_to_scalar(BigInt::from(9u8)).unwrap());
        v
    }

    #[test]
    fn recombines_root_limbs() {
        let hi = BigInt::from(0xabcdu64);
        let lo: BigInt = (BigInt::from(1u8) << 128) - 1;
        let root = issuer_root_from_show_public_values(&show_public_values(hi.clone(), lo.clone()))
            .unwrap();
        assert_eq!(root, (hi << 128) + lo);
    }

    #[test]
    fn reads_the_revocation_root_after_the_issuer_root() {
        let values = show_public_values(BigInt::from(1u8), BigInt::from(2u8));
        let root = revocation_root_from_show_public_values(&values).unwrap();
        assert_eq!(root, (BigInt::from(7u8) << 128) + 9);
    }

    #[test]
    fn rejects_an_oversized_limb() {
        let values = show_public_values(BigInt::from(1u8) << 128, BigInt::from(0u8));
        assert!(issuer_root_from_show_public_values(&values).is_err());
    }

    #[test]
    fn rejects_a_short_vector() {
        assert!(issuer_root_from_show_public_values(&[Scalar::ONE]).is_err());
    }

    /// The issuer key is private everywhere and shared after the claims; the
    /// JWT flow then shares the revocation value.
    #[test]
    fn issuer_key_is_private_and_shared() {
        let jwt = calculate_jwt_output_indices(CircuitSize::Kb1);
        assert!(jwt.issuer_key_x_index > jwt.num_public());
        let jwt_shared = jwt.shared_witness_indices();
        assert_eq!(
            jwt_shared[jwt_shared.len() - 4..],
            [
                jwt.issuer_key_x_index,
                jwt.issuer_key_y_index,
                jwt.revocation_value_index,
                jwt.revocation_value_index + 1,
            ]
        );
        let show = calculate_show_witness_indices(2, ShowVariant::Jwt);
        assert_eq!(jwt_shared.len(), show.shared_witness_indices().len());

        let mdoc = calculate_mdoc_output_indices(4);
        assert!(mdoc.issuer_key_x_index > mdoc.num_public());
        assert_eq!(
            mdoc.shared_witness_indices(2).last(),
            Some(&mdoc.issuer_key_y_index)
        );
        let show_mdoc = calculate_show_witness_indices(2, ShowVariant::Mdoc);
        assert_eq!(
            mdoc.shared_witness_indices(2).len(),
            show_mdoc.shared_witness_indices().len()
        );
    }
}

#[cfg(test)]
mod issuer_key_layout_tests {
    use super::*;

    /// Look up a signal's witness index in a compiled circuit's `.sym` file.
    fn sym_index(contents: &str, name: &str) -> Option<usize> {
        for line in contents.lines() {
            let mut parts = line.split(',');
            let _ = parts.next();
            let witness_idx = parts.next()?;
            let _ = parts.next();
            if parts.next()?.trim() == name {
                return witness_idx.parse::<i64>().ok().filter(|i| *i >= 0).map(|i| i as usize);
            }
        }
        None
    }

    fn read_sym(relative: &str) -> Option<String> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
        if !path.exists() {
            eprintln!(
                "{} not found; skipping (recompile the circuit first).",
                path.display()
            );
            return None;
        }
        Some(std::fs::read_to_string(&path).expect("read .sym"))
    }

    /// Catches public-IO drift between the compiled circuits and the layouts
    /// above. Every consumer locates these signals by index, so an added output
    /// or a reordered signal would otherwise leave them reading unrelated field
    /// elements with no other symptom.
    #[test]
    fn public_io_indices_match_jwt_sym() {
        let Some(contents) = read_sym("../circom/build/jwt_1k/jwt_1k.sym") else {
            return;
        };
        let layout = calculate_jwt_output_indices(CircuitSize::Kb1);

        for (name, expected) in [
            ("main.pubKeyX", layout.issuer_key_x_index),
            ("main.pubKeyY", layout.issuer_key_y_index),
            ("main.decodeFlags[0]", layout.decode_flags_start),
            ("main.claimFormats[0]", layout.claim_formats_start),
        ] {
            assert_eq!(
                sym_index(&contents, name),
                Some(expected),
                "{name} index drifted from jwt_1k.sym (recompile jwt and update utils.rs)"
            );
        }

        // The public prefix is contiguous, so the last public signal sits at
        // num_public(). Catches a miscounted array length.
        assert_eq!(
            sym_index(&contents, "main.claimFormats[1]"),
            Some(layout.num_public()),
            "num_public() disagrees with jwt_1k.sym"
        );
    }

    #[test]
    fn public_io_indices_match_mdoc_sym() {
        let Some(contents) = read_sym("../circom/build/mdoc/mdoc.sym") else {
            return;
        };
        let max_claims = crate::circuits::mdoc_circuit::MDOC_MAX_CLAIMS;
        let layout = calculate_mdoc_output_indices(max_claims);

        for (name, expected) in [
            ("main.pubKeyX", layout.issuer_key_x_index),
            ("main.pubKeyY", layout.issuer_key_y_index),
            ("main.valueTypes[0]", layout.value_types_start),
            ("main.claimFlags[0]", layout.claim_flags_start),
        ] {
            assert_eq!(
                sym_index(&contents, name),
                Some(expected),
                "{name} index drifted from mdoc.sym (recompile mdoc and update utils.rs)"
            );
        }

        assert_eq!(
            sym_index(&contents, &format!("main.claimFlags[{}]", max_claims - 1)),
            Some(layout.num_public()),
            "num_public() disagrees with mdoc.sym"
        );
    }
}

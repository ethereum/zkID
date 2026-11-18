use bellpepper_core::SynthesisError;
use num_bigint::BigInt;
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
/// Matches the current `Show(nClaims, maxPredicates, maxLogicTokens, valueBits)`
/// template: predicates + RPN logic expression replaced the old
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
    ];

    parse_inputs(json_value, field_defs)
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
/// 4. `pubKeyX`, `pubKeyY`, the issuer key the ES256 check ran against
/// 5. `decodeFlags[n_claims]`, `claimFormats[n_claims]`, which say how each
///    entry of `normalizedClaimValues` was produced
///
/// all declared public in `circom/circuits/main/jwt*.circom`.
///
/// The circuit has no public *outputs*: claim values would reveal the attribute
/// and the device key would link every presentation, so both travel privately
/// via `comm_W_shared`. Public inputs therefore start at witness[1]:
///   witness[1] = main.pubKeyX
///   witness[2] = main.pubKeyY
///   witness[3..3+n]   = main.decodeFlags[..]
///   witness[3+n..3+2n] = main.claimFormats[..]
/// with normalizedClaimValues and KeyBindingX/Y in the private region at
/// `CircuitSize::claim_values_witness_start`.
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
    /// Witness index of the public issuer key coordinate `pubKeyX`.
    pub issuer_key_x_index: usize,
    /// Witness index of the public issuer key coordinate `pubKeyY`.
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

    /// Public IO: issuer pubKeyX/Y + decodeFlags + claimFormats.
    ///
    /// Claim values and the device key are deliberately absent: the former would
    /// reveal the attribute, the latter would link every presentation made from
    /// this credential. Both travel privately via `comm_W_shared`.
    pub fn num_public(&self) -> usize {
        2 * self.claim_values_len + 2
    }

    /// Witness indices the shared partition must equal, in the order
    /// `PrepareCircuit::shared` pushes them:
    /// [KeyBindingX, KeyBindingY, claimValues.., claimIdentifierHashes..].
    pub fn shared_witness_indices(&self) -> Vec<usize> {
        let mut idx = vec![self.keybinding_x_index, self.keybinding_y_index];
        idx.extend(self.claim_values_range());
        idx.extend(self.claim_identifier_hashes_range());
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
    // No public outputs, so the public inputs occupy witness[1..] directly.
    let issuer_key_x_index = 1;
    let issuer_key_y_index = 2;
    let decode_flags_start = 3;
    let claim_formats_start = decode_flags_start + claim_values_len;

    JwtOutputLayout {
        claim_values_start,
        claim_values_len,
        claim_identifier_hashes_start,
        keybinding_x_index,
        keybinding_y_index,
        issuer_key_x_index,
        issuer_key_y_index,
        decode_flags_start,
        claim_formats_start,
    }
}

/// Compare the issuer key in a credential proof's public values (JWT or MDOC)
/// against the one the caller expects.
///
/// `public_values[i]` is `witness[i + 1]`, so the caller passes the layout's
/// `issuer_key_x_index` and the key is read from there. The key is not at a
/// fixed offset from the end: `decodeFlags`/`claimFormats` (JWT) and
/// `valueTypes`/`claimFlags` (MDOC) are public inputs declared after it.
///
/// Verifying applications call this to establish issuer identity, which proof
/// verification alone does not: the circuit checks the credential signature
/// against whatever key was supplied at proving time.
///
/// Returns an error when the proof carries a key other than `expected`.
pub fn check_issuer_key_binding(
    public_values: &[Scalar],
    issuer_key_x_index: usize,
    expected_x: BigInt,
    expected_y: BigInt,
) -> Result<(), String> {
    let start = issuer_key_x_index
        .checked_sub(1)
        .ok_or_else(|| "issuer key index must be a 1-based witness index".to_string())?;

    if public_values.len() < start + 2 {
        return Err(format!(
            "proof exposes {} public values, expected at least {} (issuer pubKeyX, pubKeyY at \
             witness index {})",
            public_values.len(),
            start + 2,
            issuer_key_x_index,
        ));
    }

    let expected = [expected_x, expected_y]
        .into_iter()
        .map(|v| bigint_to_scalar(v).map_err(|e| format!("invalid expected issuer key: {e:?}")))
        .collect::<Result<Vec<_>, _>>()?;

    let proven = &public_values[start..start + 2];
    if proven != expected.as_slice() {
        return Err(
            "untrusted issuer: the credential was signed by a key that is not the expected \
             issuer key"
                .to_string(),
        );
    }
    Ok(())
}

/// Show circuit template parameters (`Show(nClaims, maxPredicates, maxLogicTokens, valueBits)`).
/// Fixed across all VC sizes: the Show circuit is always `Show(2, 2, 8, 64)`
/// (see `circom/circuits.json`), so only `nClaims` varies with the JWT circuit
/// and it is always `2` because every JWT size uses `maxMatches = 4`.
pub const SHOW_MAX_PREDICATES: usize = 2;
pub const SHOW_MAX_LOGIC_TOKENS: usize = 8;
/// Fixed byte width an attribute name is hashed over (Show NAME_ID_LEN in show.circom).
pub const SHOW_NAME_ID_LEN: usize = 31;

/// Number of public IO signals of the Show circuit.
///
/// The verifier statement is bound into the proof's public IO (see
/// `circom/circuits/main/show.circom`). Circom lays the public signals out as a
/// contiguous witness prefix `witness[1..=SHOW_NUM_PUBLIC]`, in declaration order:
///   [0] expressionResult (output)
///   [1] messageHash
///   [2] predicateLen
///   [3..]  predicateClaimRefs[maxPredicates]
///          predicateOps[maxPredicates]
///          predicateRhsIsRef[maxPredicates]
///          predicateRhsValues[maxPredicates]
///          predicateClaimNames[maxPredicates][NAME_ID_LEN]
///          predicateClaimNameLens[maxPredicates]
///          predicateRhsClaimNames[maxPredicates][NAME_ID_LEN]
///          predicateRhsClaimNameLens[maxPredicates]
///          tokenTypes[maxLogicTokens]
///          tokenValues[maxLogicTokens]
///          exprLen
/// = 4 + 6*maxPredicates + 2*maxPredicates*NAME_ID_LEN + 2*maxLogicTokens
///   (maxPredicates=2, maxLogicTokens=8, NAME_ID_LEN=31: 4 + 12 + 124 + 16 = 156).
///
/// The attribute names are public so the verifier sees (and pins) which attribute
/// each predicate operand was bound to; the circuit hashes them to the identity.
pub const SHOW_NUM_PUBLIC: usize = 4
    + 6 * SHOW_MAX_PREDICATES
    + 2 * SHOW_MAX_PREDICATES * SHOW_NAME_ID_LEN
    + 2 * SHOW_MAX_LOGIC_TOKENS;

/// Layout of the Show circuit's witness vector.
///
/// Verified against `build/show/show.sym` (`Show(2, 2, 8, 64)`), with the
/// verifier statement made public (`SHOW_NUM_PUBLIC = 30`):
///   witness[1]        = main.expressionResult (public output)
///   witness[2..=30]   = messageHash + predicate program (public inputs)
///   witness[31]       = main.deviceKeyX       (private, shared via comm_W_shared)
///   witness[32]       = main.deviceKeyY       (private, shared)
///   witness[33]       = main.sig_r            (private)
///   witness[34]       = main.sig_s_inverse    (private)
///   witness[35..35+n_claims] = main.claimValues[..] (private, shared)
///   witness[35+n_claims..]   = main.claimIdentifierHashes[..] (private, shared)
#[derive(Debug, Clone, Copy)]
pub struct ShowWitnessLayout {
    pub expression_result_index: usize,
    pub device_key_x_index: usize,
    pub device_key_y_index: usize,
    pub claim_values_start: usize,
    pub claim_values_len: usize,
    pub claim_identifier_hashes_start: usize,
}

impl ShowWitnessLayout {
    pub fn claim_values_range(&self) -> Range<usize> {
        self.claim_values_start..self.claim_values_start + self.claim_values_len
    }

    pub fn claim_identifier_hashes_range(&self) -> Range<usize> {
        self.claim_identifier_hashes_start
            ..self.claim_identifier_hashes_start + self.claim_values_len
    }

    /// Number of public IO signals (`expressionResult` + bound statement).
    pub fn num_public(&self) -> usize {
        SHOW_NUM_PUBLIC
    }

    /// Witness indices the shared partition must equal, in the order
    /// `ShowCircuit::shared` pushes them.
    pub fn shared_witness_indices(&self) -> Vec<usize> {
        let mut idx = vec![self.device_key_x_index, self.device_key_y_index];
        idx.extend(self.claim_values_range());
        idx.extend(self.claim_identifier_hashes_range());
        idx
    }
}

/// Calculate Show circuit witness layout for the given `n_claims` template parameter.
///
/// `n_claims` must equal the JWT circuit's `maxMatches - 2` (see [`CircuitSize::n_claims`]).
pub fn calculate_show_witness_indices(n_claims: usize) -> ShowWitnessLayout {
    // Private signals follow the public prefix: deviceKeyX, deviceKeyY, sig_r,
    // sig_s_inverse, then claimValues[..].
    let device_key_x_index = SHOW_NUM_PUBLIC + 1;
    let claim_values_start = device_key_x_index + 4;
    ShowWitnessLayout {
        expression_result_index: 1,
        device_key_x_index,
        device_key_y_index: device_key_x_index + 1,
        claim_values_start,
        claim_values_len: n_claims,
        claim_identifier_hashes_start: claim_values_start + n_claims,
    }
}

/// Layout of the MDOC circuit's public outputs within the witness vector.
///
/// Circom lays public IO out as outputs first, then public inputs (in template
/// declaration order), so for the MDOC circuit the public prefix is:
/// 1. `validUntilDate`, the only output
/// 2. `pubKeyX`, `pubKeyY`, the issuer key the ES256 check ran against
/// 3. `valueTypes[maxClaims]`, `claimFlags[maxClaims]`, which say how each entry
///    of `normalizedClaimValues` was produced
///
/// declared public in `circom/circuits/main/mdoc.circom`. `normalizedClaimValues`
/// and `deviceKeyX`/`deviceKeyY` are private and reach Show through the shared
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
    /// Witness index of the public issuer key coordinate `pubKeyX`.
    pub issuer_key_x_index: usize,
    /// Witness index of the public issuer key coordinate `pubKeyY`.
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

    /// Public IO: the validUntilDate output, then issuer pubKeyX/Y + valueTypes +
    /// claimFlags inputs. Claim values and the device key are private — see
    /// [`JwtOutputLayout::num_public`].
    pub fn num_public(&self) -> usize {
        2 * self.claim_values_len + 3
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
        idx
    }
}

/// Calculate MDOC circuit witness layout from `maxClaims`.
///
/// Verified against `build/mdoc/mdoc.sym` (`MDOC(1792, 256, 4, 32, 64)`):
///   witness[1]    = main.validUntilDate  (public output)
///   witness[2]    = main.pubKeyX         (public input)
///   witness[2966] = main.normalizedClaimValues[0] (private, shared)
///   witness[2970] = main.claimIdentifierHashes[0]  (private, shared)
///   witness[2974] = main.deviceKeyX      (private, shared)
pub fn calculate_mdoc_output_indices(max_claims: usize) -> MdocOutputLayout {
    // The lone public output occupies witness[1]; the public inputs follow.
    let issuer_key_x_index = 2;
    let issuer_key_y_index = 3;
    let value_types_start = 4;
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

    /// Catches witness-layout drift between show.sym and calculate_show_witness_indices,
    /// which would silently break the Prepare<->Show commitment binding.
    #[test]
    fn witness_indices_match_show_sym() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let sym_path = std::path::Path::new(manifest_dir)
            .join("../circom/build/show/show.sym");
        if !sym_path.exists() {
            eprintln!(
                "show.sym not found at {}; skipping (run `bash ../circom/scripts/compile.sh show`).",
                sym_path.display()
            );
            return;
        }

        let contents = std::fs::read_to_string(&sym_path).expect("read show.sym");
        let idx_of = |name: &str| -> Option<usize> {
            for line in contents.lines() {
                let mut parts = line.split(',');
                let _ = parts.next();
                let witness_idx = parts.next()?;
                let _ = parts.next();
                let signal = parts.next()?.trim();
                if signal == name {
                    let parsed: i64 = witness_idx.parse().ok()?;
                    if parsed < 0 {
                        return None;
                    }
                    return Some(parsed as usize);
                }
            }
            None
        };

        let expression_result = idx_of("main.expressionResult")
            .expect("main.expressionResult missing from show.sym");
        let device_key_x =
            idx_of("main.deviceKeyX").expect("main.deviceKeyX missing from show.sym");
        let device_key_y =
            idx_of("main.deviceKeyY").expect("main.deviceKeyY missing from show.sym");
        let claim0 =
            idx_of("main.claimValues[0]").expect("main.claimValues[0] missing from show.sym");

        let layout = calculate_show_witness_indices(2);
        assert_eq!(
            layout.expression_result_index, expression_result,
            "expressionResult witness index mismatch with show.sym"
        );
        assert_eq!(
            layout.device_key_x_index, device_key_x,
            "deviceKeyX witness index mismatch with show.sym (recompile show and update utils.rs)"
        );
        assert_eq!(
            layout.device_key_y_index, device_key_y,
            "deviceKeyY witness index mismatch with show.sym (recompile show and update utils.rs)"
        );
        assert_eq!(
            layout.claim_values_start, claim0,
            "claimValues[0] witness index mismatch with show.sym"
        );
    }
}

#[cfg(test)]
mod issuer_key_binding_tests {
    use super::*;

    fn scalars(values: &[u64]) -> Vec<Scalar> {
        values
            .iter()
            .map(|v| bigint_to_scalar(BigInt::from(*v)).unwrap())
            .collect()
    }

    /// A JWT public-IO vector: the issuer key, then decodeFlags and
    /// claimFormats. Claim values and the device key are private.
    fn jwt_public_values(key_x: u64, key_y: u64) -> Vec<Scalar> {
        scalars(&[key_x, key_y, 1, 1, 1, 3])
    }

    const JWT_KEY_INDEX: usize = 1;

    /// A proof carrying the expected key at the layout's index is accepted,
    /// whatever surrounds it (claim outputs, device key, normalization).
    #[test]
    fn accepts_the_expected_issuer_key() {
        assert!(check_issuer_key_binding(
            &jwt_public_values(42, 43),
            JWT_KEY_INDEX,
            BigInt::from(42),
            BigInt::from(43),
        )
        .is_ok());
    }

    /// A proof built under a different issuer key is rejected. This is the case
    /// the check exists for: such a proof verifies normally, so only the key
    /// comparison distinguishes it.
    #[test]
    fn rejects_a_different_issuer_key() {
        let err = check_issuer_key_binding(
            &jwt_public_values(999, 1000),
            JWT_KEY_INDEX,
            BigInt::from(42),
            BigInt::from(43),
        )
        .expect_err("proof under an unexpected issuer key must be rejected");
        assert!(err.contains("untrusted issuer"), "unexpected error: {err}");
    }

    /// Half a match is still a mismatch: both coordinates must agree.
    #[test]
    fn rejects_a_partial_key_match() {
        assert!(check_issuer_key_binding(
            &jwt_public_values(42, 1000),
            JWT_KEY_INDEX,
            BigInt::from(42),
            BigInt::from(43),
        )
        .is_err());
    }

    /// A truncated public-IO vector fails closed rather than panicking.
    #[test]
    fn rejects_a_short_public_value_vector() {
        let public_values = scalars(&[42]);
        let err = check_issuer_key_binding(
            &public_values,
            JWT_KEY_INDEX,
            BigInt::from(42),
            BigInt::from(43),
        )
        .expect_err("a vector shorter than the issuer key must be rejected");
        assert!(err.contains("expected at least 2"), "unexpected error: {err}");
    }

    /// The issuer key sits in the middle of the public IO, not at its end:
    /// `decodeFlags`/`claimFormats` are public inputs declared after it. Pins
    /// the property that makes locating it by index necessary.
    #[test]
    fn issuer_key_is_not_the_trailing_public_pair() {
        let jwt = calculate_jwt_output_indices(CircuitSize::Kb1);
        assert_eq!(jwt.issuer_key_x_index, JWT_KEY_INDEX);
        assert!(
            jwt.issuer_key_y_index < jwt.num_public(),
            "public inputs follow the issuer key, so it is not the trailing pair"
        );

        let mdoc = calculate_mdoc_output_indices(4);
        assert!(mdoc.issuer_key_y_index < mdoc.num_public());
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

use std::{fmt, str::FromStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitSize {
    Kb1,
    Kb2,
    Kb4,
    Kb8,
}

impl CircuitSize {
    pub const ALL: [CircuitSize; 4] = [
        CircuitSize::Kb1,
        CircuitSize::Kb2,
        CircuitSize::Kb4,
        CircuitSize::Kb8,
    ];

    pub fn circuit_name(self) -> &'static str {
        match self {
            CircuitSize::Kb1 => "jwt_1k",
            CircuitSize::Kb2 => "jwt_2k",
            CircuitSize::Kb4 => "jwt_4k",
            CircuitSize::Kb8 => "jwt_8k",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            CircuitSize::Kb1 => "1k",
            CircuitSize::Kb2 => "2k",
            CircuitSize::Kb4 => "4k",
            CircuitSize::Kb8 => "8k",
        }
    }

    pub fn max_message_length(self) -> usize {
        match self {
            CircuitSize::Kb1 => 1280,
            CircuitSize::Kb2 => 2048,
            CircuitSize::Kb4 => 4096,
            CircuitSize::Kb8 => 8192,
        }
    }

    pub fn max_b64_payload_length(self) -> usize {
        match self {
            CircuitSize::Kb1 => 960,
            CircuitSize::Kb2 => 2000,
            CircuitSize::Kb4 => 4000,
            CircuitSize::Kb8 => 8000,
        }
    }

    pub fn max_matches(self) -> usize {
        4
    }
    pub fn max_substring_length(self) -> usize {
        50
    }

    pub fn max_claims_length(self) -> usize {
        128
    }

    /// Number of claim slots used by the JWT circuit and exposed as
    /// `normalizedClaimValues`. Equal to `max_matches - 2` because the first two
    /// match slots are reserved for the device-binding key (`"x":"` / `"y":"`).
    /// This must equal the Show circuit's `nClaims` template parameter.
    pub fn n_claims(self) -> usize {
        self.max_matches() - 2
    }

    /// Witness index of `main.normalizedClaimValues[0]` in the compiled JWT circuit.
    ///
    /// The JWT circuit has **no public outputs**: normalized claim values would
    /// publish the exact claim (a date of birth), and the device key would
    /// publish a constant per-credential identifier that survives reblinding and
    /// lets a verifier recognize a returning holder. Both are private signals
    /// reaching Show through the shared witness commitment, which puts them
    /// among the intermediates at offsets that shift with `maxMessageLength` —
    /// hence the per-size table.
    ///
    /// `KeyBindingX/Y` follow immediately after the claim values, matching their
    /// declaration order in `jwt.circom`.
    ///
    /// `tests/witness_layout.rs` re-derives every value from the circuit's `.sym`
    /// file, so a recompile that moves these fails loudly instead of silently
    /// reading the wrong slot.
    pub fn claim_values_witness_start(self) -> usize {
        match self {
            CircuitSize::Kb1 => 2463,
            CircuitSize::Kb2 => 4011,
            CircuitSize::Kb4 => 7559,
            CircuitSize::Kb8 => 14655,
        }
    }

    /// Witness index of `main.claimIdentifierHashes[0]` in each compiled JWT
    /// circuit. Follows normalizedClaimValues[maxClaims] (with the name-extractor
    /// internal signals in between), and is immediately followed by KeyBindingX/Y.
    /// Re-derived from each `.sym` by `tests/witness_layout.rs`.
    pub fn claim_identifier_hashes_witness_start(self) -> usize {
        match self {
            CircuitSize::Kb1 => 2527,
            CircuitSize::Kb2 => 4075,
            CircuitSize::Kb4 => 7623,
            CircuitSize::Kb8 => 14719,
        }
    }
}

impl Default for CircuitSize {
    fn default() -> Self {
        CircuitSize::Kb1
    }
}

impl fmt::Display for CircuitSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CircuitSize {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "1k" => Ok(CircuitSize::Kb1),
            "2k" => Ok(CircuitSize::Kb2),
            "4k" => Ok(CircuitSize::Kb4),
            "8k" => Ok(CircuitSize::Kb8),
            other => Err(format!(
                "Unknown circuit size '{}'. Valid values: 1k, 2k, 4k, 8k",
                other
            )),
        }
    }
}

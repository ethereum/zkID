//! Path config for cross-platform compatibility.

use crate::circuit_size::CircuitSize;
use std::path::{Path, PathBuf};

/// Path config for all file operations.
///
/// This struct replaces the previous pattern of changing the global working directory,
/// providing explicit, thread-safe path resolution.

#[derive(Clone, Debug)]
pub struct PathConfig {
    /// Base directory for all file operations (Documents dir on mobile, cwd in dev)
    pub base_dir: PathBuf,
    /// Whether running in mobile environment (affects path resolution patterns)
    pub is_mobile: bool,
    /// JWT circuit size variant.  Ignored when `is_mobile` is true.
    pub circuit_size: CircuitSize,
}

impl Default for PathConfig {
    fn default() -> Self {
        Self::development()
    }
}

impl PathConfig {
    /// Create a new PathConfig with explicit settings.
    pub fn new(base_dir: impl Into<PathBuf>, is_mobile: bool) -> Self {
        Self {
            base_dir: base_dir.into(),
            is_mobile,
            circuit_size: CircuitSize::default(),
        }
    }

    /// Create config for mobile environment.
    ///
    /// Mobile apps typically extract assets to a Documents directory with a flat structure:
    /// - `{documents}/jwt_input.json`
    /// - `{documents}/show_input.json`
    /// - `{documents}/keys/*.key`
    /// - `{documents}/circom/build/jwt/jwt_js/jwt.r1cs`

    pub fn mobile(documents_path: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: documents_path.into(),
            is_mobile: true,
            circuit_size: CircuitSize::default(),
        }
    }

    /// Create config for development environment.
    ///
    /// Development uses nested paths relative to the current working directory:
    /// - `../circom/inputs/jwt/1k/default.json`
    /// - `../circom/inputs/show/1k/default.json`
    /// - `keys/1k_*.key`
    /// - `../circom/build/jwt_1k/jwt_1k_js/jwt_1k.r1cs`
    pub fn development() -> Self {
        Self {
            base_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            is_mobile: false,
            circuit_size: CircuitSize::default(),
        }
    }

    /// Create config for development environment with an explicit circuit size.
    pub fn development_with_size(circuit_size: CircuitSize) -> Self {
        Self {
            base_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            is_mobile: false,
            circuit_size,
        }
    }

    /// Resolve the input JSON path for a circuit.
    ///
    /// MDOC has no size variants, so its input lives at `inputs/mdoc/default.json`.
    pub fn input_json(&self, circuit: &str) -> PathBuf {
        if self.is_mobile {
            self.base_dir.join(format!("{}_input.json", circuit))
        } else if circuit == "mdoc" {
            self.base_dir
                .join("../circom/inputs/mdoc/default.json")
        } else {
            self.base_dir.join(format!(
                "../circom/inputs/{}/{}/default.json",
                circuit,
                self.circuit_size.as_str()
            ))
        }
    }

    /// Resolve the R1CS file path for a circuit.
    ///
    /// For `"jwt"` the size-specific circuit name is used (e.g. `jwt_1k`).
    /// For `"show"` (and any other circuit) the name is used verbatim.
    /// Mobile paths are unchanged.
    pub fn r1cs_path(&self, circuit: &str) -> PathBuf {
        if self.is_mobile {
            self.base_dir
                .join("../circom/build")
                .join(circuit)
                .join(format!("{}_js", circuit))
                .join(format!("{}.r1cs", circuit))
        } else {
            let name = if circuit == "jwt" {
                self.circuit_size.circuit_name()
            } else {
                circuit
            };
            self.base_dir
                .join("../circom/build")
                .join(name)
                .join(format!("{}_js", name))
                .join(format!("{}.r1cs", name))
        }
    }

    /// Resolve a key file path (proving/verifying keys).
    ///
    /// On mobile the name is used verbatim.
    /// In development the size label is prepended: `keys/1k_prepare_proving.key`.
    pub fn key_path(&self, name: &str) -> PathBuf {
        if self.is_mobile {
            self.keys_dir().join(name)
        } else {
            self.keys_dir()
                .join(format!("{}_{}", self.circuit_size.as_str(), name))
        }
    }

    /// Resolve an artifact file path (proofs, witnesses, instances).
    ///
    /// Same size-prefixing rules as `key_path`.
    pub fn artifact_path(&self, name: &str) -> PathBuf {
        if self.is_mobile {
            self.keys_dir().join(name)
        } else {
            self.keys_dir()
                .join(format!("{}_{}", self.circuit_size.as_str(), name))
        }
    }

    /// Directory holding keys and artifacts.
    pub fn keys_dir(&self) -> PathBuf {
        self.base_dir.join("keys")
    }

    /// Resolve the shared blinds file path.
    pub fn shared_blinds_path(&self) -> PathBuf {
        self.artifact_path("shared_blinds.bin")
    }

    /// Resolve an absolute path, joining relative paths with base_dir.
    ///
    /// If the path is already absolute, it's returned as-is.
    /// Otherwise, it's joined with the base directory.
    pub fn resolve(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.base_dir.join(path)
        }
    }
}

// Key file name constants
pub mod keys {
    pub const PREPARE_PROVING_KEY: &str = "prepare_proving.key";
    pub const PREPARE_VERIFYING_KEY: &str = "prepare_verifying.key";
    pub const SHOW_PROVING_KEY: &str = "show_proving.key";
    pub const SHOW_VERIFYING_KEY: &str = "show_verifying.key";
    pub const PREPARE_PROOF: &str = "prepare_proof.bin";
    pub const PREPARE_WITNESS: &str = "prepare_witness.bin";
    pub const PREPARE_INSTANCE: &str = "prepare_instance.bin";
    pub const SHOW_PROOF: &str = "show_proof.bin";
    pub const SHOW_WITNESS: &str = "show_witness.bin";
    pub const SHOW_INSTANCE: &str = "show_instance.bin";
    pub const SHARED_BLINDS: &str = "shared_blinds.bin";
    pub const MDOC_PROVING_KEY: &str = "mdoc_proving.key";
    pub const MDOC_VERIFYING_KEY: &str = "mdoc_verifying.key";
    pub const MDOC_PROOF: &str = "mdoc_proof.bin";
    pub const MDOC_WITNESS: &str = "mdoc_witness.bin";
    pub const MDOC_INSTANCE: &str = "mdoc_instance.bin";
    pub const SHA256_PROVING_KEY: &str = "sha256_2048_proving.key";
    pub const SHA256_VERIFYING_KEY: &str = "sha256_2048_verifying.key";
    pub const SHA256_PROOF: &str = "sha256_2048_proof.bin";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mobile_config() {
        let config = PathConfig::mobile("/app/Documents");

        assert_eq!(
            config.input_json("jwt"),
            PathBuf::from("/app/Documents/jwt_input.json")
        );
        assert_eq!(
            config.input_json("show"),
            PathBuf::from("/app/Documents/show_input.json")
        );
        assert_eq!(
            config.key_path("prepare_proving.key"),
            PathBuf::from("/app/Documents/keys/prepare_proving.key")
        );
    }

    #[test]
    fn test_development_config_default_size() {
        let config = PathConfig::new("/project", false);

        assert_eq!(
            config.input_json("jwt"),
            PathBuf::from("/project/../circom/inputs/jwt/1k/default.json")
        );
        assert_eq!(
            config.input_json("show"),
            PathBuf::from("/project/../circom/inputs/show/1k/default.json")
        );
        assert_eq!(
            config.r1cs_path("jwt"),
            PathBuf::from("/project/../circom/build/jwt_1k/jwt_1k_js/jwt_1k.r1cs")
        );
        assert_eq!(
            config.r1cs_path("show"),
            PathBuf::from("/project/../circom/build/show/show_js/show.r1cs")
        );
        assert_eq!(
            config.key_path("prepare_proving.key"),
            PathBuf::from("/project/keys/1k_prepare_proving.key")
        );
    }

    #[test]
    fn test_development_config_explicit_size() {
        let config = PathConfig {
            base_dir: PathBuf::from("/project"),
            is_mobile: false,
            circuit_size: CircuitSize::Kb4,
        };

        assert_eq!(
            config.input_json("jwt"),
            PathBuf::from("/project/../circom/inputs/jwt/4k/default.json")
        );
        assert_eq!(
            config.r1cs_path("jwt"),
            PathBuf::from("/project/../circom/build/jwt_4k/jwt_4k_js/jwt_4k.r1cs")
        );
        assert_eq!(
            config.key_path("prepare_proving.key"),
            PathBuf::from("/project/keys/4k_prepare_proving.key")
        );
    }

    #[test]
    fn test_mdoc_paths_skip_size_subdir() {
        let config = PathConfig::new("/project", false);
        assert_eq!(
            config.input_json("mdoc"),
            PathBuf::from("/project/../circom/inputs/mdoc/default.json")
        );
        assert_eq!(
            config.r1cs_path("mdoc"),
            PathBuf::from("/project/../circom/build/mdoc/mdoc_js/mdoc.r1cs")
        );
    }

    #[test]
    fn test_resolve_absolute() {
        let config = PathConfig::mobile("/app/Documents");

        let absolute = PathBuf::from("/custom/path/input.json");
        assert_eq!(config.resolve(&absolute), absolute);
    }

    #[test]
    fn test_resolve_relative() {
        let config = PathConfig::mobile("/app/Documents");

        let relative = PathBuf::from("custom/input.json");
        assert_eq!(
            config.resolve(&relative),
            PathBuf::from("/app/Documents/custom/input.json")
        );
    }
}

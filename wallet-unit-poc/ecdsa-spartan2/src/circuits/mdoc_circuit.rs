use super::{bind_shared, synthesize_all_vars, synthesize_witness_only};
use crate::{
    paths::PathConfig, prover::generate_mdoc_witness, utils::calculate_mdoc_output_indices, Scalar,
    E,
};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circom_scotia::reader::load_r1cs;
use ff::Field;
use spartan2::traits::circuit::SpartanCircuit;
use std::{
    any::type_name,
    path::PathBuf,
    sync::{Arc, Mutex},
};

// MDOC circuit template params: MDOC(1792, 256, 4, 32, 64, 64).
pub const MDOC_MAX_CRED_LEN: usize = 1792;
pub const MDOC_MAX_PREIMAGE_LEN: usize = 256;
pub const MDOC_MAX_CLAIMS: usize = 4;
pub const MDOC_MAX_IDENTIFIER_LEN: usize = 32;
pub const MDOC_MAX_VALUE_LEN: usize = 64;
pub const MDOC_MAX_DEVICE_KEY_PREFIX_LEN: usize = 64;

// Must equal the Show circuit's `nClaims` template parameter; otherwise the
// post-reblind `comm_W_shared` commitments won't match between MDOC and Show.
pub const MDOC_SHARED_CLAIMS: usize = 2;

#[cfg(all(feature = "native-witness", has_circuit_mdoc))]
witnesscalc_adapter::witness!(mdoc);

#[cfg(feature = "native-witness")]
pub(crate) fn call_mdoc_witness(inputs_json: &str) -> Result<Vec<u8>, SynthesisError> {
    #[cfg(has_circuit_mdoc)]
    {
        return mdoc_witness(inputs_json).map_err(|_| SynthesisError::Unsatisfiable);
    }
    #[cfg(not(has_circuit_mdoc))]
    {
        let _ = inputs_json;
        eprintln!(
            "MDOC circuit not compiled into this binary.\n\
             Run `pnpm compile:mdoc && cargo build --release` first."
        );
        Err(SynthesisError::Unsatisfiable)
    }
}

#[cfg(not(feature = "native-witness"))]
pub(crate) fn call_mdoc_witness(_inputs_json: &str) -> Result<Vec<u8>, SynthesisError> {
    Err(SynthesisError::Unsatisfiable)
}

#[derive(Debug, Clone)]
pub struct MdocCircuit {
    path_config: PathConfig,
    input_path: Option<PathBuf>,
    cached_witness: Arc<Mutex<Option<Vec<Scalar>>>>,
}

impl Default for MdocCircuit {
    fn default() -> Self {
        Self {
            path_config: PathConfig::default(),
            input_path: None,
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }
}

impl MdocCircuit {
    pub fn new(path_config: PathConfig, input_path: Option<PathBuf>) -> Self {
        Self {
            path_config,
            input_path,
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }

    pub fn with_witness(witness: Vec<Scalar>) -> Self {
        Self {
            path_config: PathConfig::default(),
            input_path: None,
            cached_witness: Arc::new(Mutex::new(Some(witness))),
        }
    }

    fn r1cs_path(&self) -> PathBuf {
        self.path_config.r1cs_path("mdoc")
    }

    fn get_or_generate_witness(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let mut cache = self.cached_witness.lock().unwrap();
        if let Some(ref witness) = *cache {
            return Ok(witness.clone());
        }
        let witness = generate_mdoc_witness(
            &self.path_config,
            self.input_path.as_ref().map(|p| p.as_path()),
        )?;
        *cache = Some(witness.clone());
        Ok(witness)
    }
}

impl SpartanCircuit<E> for MdocCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let cs_type = type_name::<CS>();
        let is_setup_phase = cs_type.contains("ShapeCS");
        let layout = calculate_mdoc_output_indices(MDOC_MAX_CLAIMS);
        let shared_claims = MDOC_SHARED_CLAIMS.min(layout.claim_values_len);
        let shared_indices = layout.shared_witness_indices(shared_claims);

        if is_setup_phase {
            let r1cs =
                load_r1cs(&self.r1cs_path()).map_err(|_| SynthesisError::AssignmentMissing)?;
            let vars = synthesize_all_vars(cs, r1cs, None)?;
            bind_shared(cs, shared, &vars, &shared_indices)?;
            return Ok(());
        }

        let witness = self.get_or_generate_witness()?;

        match load_r1cs::<Scalar>(&self.r1cs_path()) {
            Ok(r1cs) => {
                let vars = synthesize_all_vars(cs, r1cs, Some(witness))?;
                bind_shared(cs, shared, &vars, &shared_indices)?;
            }
            Err(_) => {
                synthesize_witness_only(cs, &witness, layout.num_public())?;
            }
        }
        Ok(())
    }

    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let layout = calculate_mdoc_output_indices(MDOC_MAX_CLAIMS);
        let num_public = layout.num_public();

        let witness = self.get_or_generate_witness().ok();

        let mut values = Vec::with_capacity(num_public);
        for idx in 1..=num_public {
            values.push(witness.as_ref().map(|w| w[idx]).unwrap_or(Scalar::ZERO));
        }
        Ok(values)
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let layout = calculate_mdoc_output_indices(MDOC_MAX_CLAIMS);

        let witness = {
            let cache = self.cached_witness.lock().unwrap();
            cache.clone()
        }
        // Not gated on `input_path`: it is `None` on every native pipeline path,
        // which used to leave the shared partition all zeros while `synthesize`
        // used the real witness. Nothing caught it because the shared variables
        // were unconstrained, so `comm_W_shared` compared commitments to zeros
        // and matched trivially. `bind_shared` now constrains these, so they
        // must come from the same witness `synthesize` sees.
        .or_else(|| self.get_or_generate_witness().ok());

        let device_key_x = witness
            .as_ref()
            .map(|w| w[layout.device_key_x_index])
            .unwrap_or(Scalar::ZERO);
        let device_key_y = witness
            .as_ref()
            .map(|w| w[layout.device_key_y_index])
            .unwrap_or(Scalar::ZERO);

        let dk_x_alloc = AllocatedNum::alloc(cs.namespace(|| "deviceKeyX"), || Ok(device_key_x))?;
        let dk_y_alloc = AllocatedNum::alloc(cs.namespace(|| "deviceKeyY"), || Ok(device_key_y))?;

        // Shared layout (must match `ShowCircuit::shared`):
        //   [deviceKeyX, deviceKeyY,
        //    normalizedClaimValues[0..MDOC_SHARED_CLAIMS],
        //    claimIdentifierHashes[0..MDOC_SHARED_CLAIMS]]
        let shared_claims = MDOC_SHARED_CLAIMS.min(layout.claim_values_len);
        let mut shared_values = Vec::with_capacity(2 + 2 * shared_claims);
        shared_values.push(dk_x_alloc);
        shared_values.push(dk_y_alloc);

        for idx in 0..shared_claims {
            let claim_scalar = witness
                .as_ref()
                .map(|w| w[layout.claim_values_start + idx])
                .unwrap_or(Scalar::ZERO);
            let claim_alloc =
                AllocatedNum::alloc(cs.namespace(|| format!("ClaimValue{idx}")), move || {
                    Ok(claim_scalar)
                })?;
            shared_values.push(claim_alloc);
        }

        for idx in 0..shared_claims {
            let id_scalar = witness
                .as_ref()
                .map(|w| w[layout.claim_identifier_hashes_start + idx])
                .unwrap_or(Scalar::ZERO);
            let id_alloc = AllocatedNum::alloc(
                cs.namespace(|| format!("ClaimIdentifierHash{idx}")),
                move || Ok(id_scalar),
            )?;
            shared_values.push(id_alloc);
        }

        Ok(shared_values)
    }

    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        _cs: &mut CS,
        _shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }

    fn num_challenges(&self) -> usize {
        0
    }
}

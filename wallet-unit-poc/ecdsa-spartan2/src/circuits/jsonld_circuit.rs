use super::{bind_shared, synthesize_all_vars, synthesize_witness_only};
use crate::{
    paths::PathConfig, prover::generate_jsonld_witness, utils::calculate_jsonld_output_indices, Scalar,
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

// `maxClaims` template parameter of JSONLD (circuits.json params[1]); the other
// dimensions are read off the input JSON's array shapes.
pub const JSONLD_MAX_CLAIMS: usize = 2;

// Must equal the Show circuit's `nClaims` template parameter; otherwise the
// post-reblind `comm_W_shared` commitments won't match between JSONLD and Show.
pub const JSONLD_SHARED_CLAIMS: usize = 2;

#[cfg(all(feature = "native-witness", has_circuit_jsonld))]
witnesscalc_adapter::witness!(jsonld);

#[cfg(feature = "native-witness")]
pub(crate) fn call_jsonld_witness(inputs_json: &str) -> Result<Vec<u8>, SynthesisError> {
    #[cfg(has_circuit_jsonld)]
    {
        return jsonld_witness(inputs_json).map_err(|_| SynthesisError::Unsatisfiable);
    }
    #[cfg(not(has_circuit_jsonld))]
    {
        let _ = inputs_json;
        eprintln!(
            "JSONLD circuit not compiled into this binary.\n\
             Run `bash ../circom/scripts/compile.sh jsonld && cargo build --release` first."
        );
        Err(SynthesisError::Unsatisfiable)
    }
}

#[cfg(not(feature = "native-witness"))]
pub(crate) fn call_jsonld_witness(_inputs_json: &str) -> Result<Vec<u8>, SynthesisError> {
    Err(SynthesisError::Unsatisfiable)
}

#[derive(Debug, Clone)]
pub struct JsonLdCircuit {
    path_config: PathConfig,
    input_path: Option<PathBuf>,
    cached_witness: Arc<Mutex<Option<Vec<Scalar>>>>,
}

impl Default for JsonLdCircuit {
    fn default() -> Self {
        Self {
            path_config: PathConfig::default(),
            input_path: None,
            cached_witness: Arc::new(Mutex::new(None)),
        }
    }
}

impl JsonLdCircuit {
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
        self.path_config.r1cs_path("jsonld")
    }

    fn get_or_generate_witness(&self) -> Result<Vec<Scalar>, SynthesisError> {
        let mut cache = self.cached_witness.lock().unwrap();
        if let Some(ref witness) = *cache {
            return Ok(witness.clone());
        }
        let witness = generate_jsonld_witness(
            &self.path_config,
            self.input_path.as_ref().map(|p| p.as_path()),
        )?;
        *cache = Some(witness.clone());
        Ok(witness)
    }
}

impl SpartanCircuit<E> for JsonLdCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let cs_type = type_name::<CS>();
        let is_setup_phase = cs_type.contains("ShapeCS");
        let layout = calculate_jsonld_output_indices(JSONLD_MAX_CLAIMS);
        let shared_claims = JSONLD_SHARED_CLAIMS.min(layout.claim_values_len);
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
        let num_public = calculate_jsonld_output_indices(JSONLD_MAX_CLAIMS).num_public();
        let witness = self.get_or_generate_witness().ok();
        Ok((1..=num_public)
            .map(|idx| witness.as_ref().map_or(Scalar::ZERO, |w| w[idx]))
            .collect())
    }

    // Layout (must match `ShowCircuit::shared`): see `shared_witness_indices`.
    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let layout = calculate_jsonld_output_indices(JSONLD_MAX_CLAIMS);
        let shared_claims = JSONLD_SHARED_CLAIMS.min(layout.claim_values_len);

        // Must be the same witness `synthesize` sees, whether or not `input_path`
        // is set: `bind_shared` constrains these values against it.
        let cached = self.cached_witness.lock().unwrap().clone();
        let witness = cached.or_else(|| self.get_or_generate_witness().ok());

        layout
            .shared_witness_indices(shared_claims)
            .into_iter()
            .enumerate()
            .map(|(i, idx)| {
                let value = witness.as_ref().map_or(Scalar::ZERO, |w| w[idx]);
                AllocatedNum::alloc(cs.namespace(|| format!("Shared{i}")), || Ok(value))
            })
            .collect()
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

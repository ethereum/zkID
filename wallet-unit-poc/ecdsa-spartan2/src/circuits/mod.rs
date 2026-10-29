pub mod mdoc_circuit;
pub mod prepare_circuit;
pub mod sha256_circuit;
pub mod show_circuit;

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, LinearCombination, SynthesisError};
use circom_scotia::r1cs::R1CS;
use ff::PrimeField;

/// Synthesize a Circom R1CS and return **every** allocated variable.
///
/// Identical to `circom_scotia::synthesize`, which returns only the public
/// outputs. We need all of them so `bind_shared` can constrain the shared
/// witness variables against arbitrary (including private) circuit signals.
///
/// Variable ordering mirrors the Circom witness: `vars[i]` corresponds to
/// `witness[i + 1]`, public inputs/outputs first, then aux signals.
pub fn synthesize_all_vars<F: PrimeField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    r1cs: R1CS<F>,
    witness: Option<Vec<F>>,
) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
    let witness = &witness;
    let mut vars: Vec<AllocatedNum<F>> = vec![];

    for i in 1..r1cs.num_inputs {
        let f: F = match witness {
            None => F::ONE,
            Some(w) => w[i],
        };
        vars.push(AllocatedNum::alloc_input(
            cs.namespace(|| format!("public_{}", i)),
            || Ok(f),
        )?);
    }

    for i in 0..r1cs.num_aux {
        let f: F = match witness {
            None => F::ONE,
            Some(w) => w[i + r1cs.num_inputs],
        };
        vars.push(AllocatedNum::alloc(
            cs.namespace(|| format!("aux_{}", i)),
            || Ok(f),
        )?);
    }

    let make_lc = |lc_data: Vec<(usize, F)>| {
        lc_data.iter().fold(
            LinearCombination::<F>::zero(),
            |lc: LinearCombination<F>, (index, coeff)| {
                lc + if *index > 0 {
                    (*coeff, vars[*index - 1].get_variable())
                } else {
                    (*coeff, CS::one())
                }
            },
        )
    };

    for (i, constraint) in r1cs.constraints.into_iter().enumerate() {
        cs.enforce(
            || format!("constraint {}", i),
            |_| make_lc(constraint.0),
            |_| make_lc(constraint.1),
            |_| make_lc(constraint.2),
        );
    }

    Ok(vars)
}

/// Constrain each shared witness variable to the circuit signal it claims to be.
///
/// `shared()` allocates its own variables and fills them from the witness, but
/// nothing in the R1CS tied them to the corresponding Circom signals — so
/// `comm_W_shared` proved only that Prepare and Show used the *same* shared
/// vector, not that the vector matched either circuit's real values. Without
/// these constraints a prover can put arbitrary values in the shared partition
/// and evaluate Show's predicates over a claim the credential never contained.
///
/// `witness_indices[k]` is the Circom witness index that `shared[k]` must equal,
/// in the same order `shared()` pushed them.
pub fn bind_shared<F: PrimeField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    shared: &[AllocatedNum<F>],
    vars: &[AllocatedNum<F>],
    witness_indices: &[usize],
) -> Result<(), SynthesisError> {
    if shared.len() != witness_indices.len() {
        return Err(SynthesisError::Unsatisfiable);
    }

    for (k, &w_idx) in witness_indices.iter().enumerate() {
        // vars[i] holds witness[i + 1]; index 0 is the constant-1 signal.
        let var = vars.get(w_idx - 1).ok_or(SynthesisError::Unsatisfiable)?;
        cs.enforce(
            || format!("shared_binding_{}", k),
            |lc| lc + shared[k].get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + var.get_variable(),
        );
    }

    Ok(())
}

/// Allocate witness variables without adding constraints.
///
/// During proving, Spartan2 only reads witness values from the constraint system;
/// the proving key already contains the R1CS constraint matrices (A, B, C).
/// This allows proving without loading the R1CS file from disk, enabling
/// proof generation in browser/WASM environments.
pub fn synthesize_witness_only<F: PrimeField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    witness: &[F],
    num_public: usize,
) -> Result<(), SynthesisError> {
    let num_inputs = 1 + num_public;
    if witness.len() < num_inputs {
        return Err(SynthesisError::Unsatisfiable);
    }
    let num_aux = witness.len() - num_inputs;

    for i in 1..num_inputs {
        AllocatedNum::alloc_input(cs.namespace(|| format!("public_{}", i)), || Ok(witness[i]))?;
    }
    for i in 0..num_aux {
        AllocatedNum::alloc(cs.namespace(|| format!("aux_{}", i)), || {
            Ok(witness[i + num_inputs])
        })?;
    }
    Ok(())
}

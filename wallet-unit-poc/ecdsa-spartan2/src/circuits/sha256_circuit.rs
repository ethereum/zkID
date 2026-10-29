//! SHA-256 over a fixed-length preimage, ported from the coordination network's
//! bellpepper circuit so both stacks prove the same statement.
//!
//! The preimage is private and the 256 digest bits are public inputs.

use crate::{Scalar, E};
use bellpepper::gadgets::sha256::sha256;
use bellpepper_core::{
    boolean::{AllocatedBit, Boolean},
    num::AllocatedNum,
    ConstraintSystem, SynthesisError,
};
use ff::Field;
use sha2::{Digest, Sha256};
use spartan2::traits::circuit::SpartanCircuit;

pub const SHA256_MESSAGE_LEN: usize = 2048;

/// Byte `i` is `i mod 256`. The Noir benchmark hashes the same message.
pub fn sha256_fixed_message() -> Vec<u8> {
    (0..SHA256_MESSAGE_LEN).map(|i| (i % 256) as u8).collect()
}

/// Digest bits, most significant bit of each byte first, as public values.
pub fn sha256_digest_bits(preimage: &[u8]) -> Vec<Scalar> {
    Sha256::digest(preimage)
        .iter()
        .flat_map(|&byte| {
            (0..8).rev().map(move |i| {
                if (byte >> i) & 1 == 1 {
                    Scalar::ONE
                } else {
                    Scalar::ZERO
                }
            })
        })
        .collect()
}

#[derive(Clone, Debug)]
pub struct Sha256Circuit {
    preimage: Vec<u8>,
}

impl Sha256Circuit {
    pub fn new(preimage: Vec<u8>) -> Self {
        Self { preimage }
    }

    pub fn fixed() -> Self {
        Self::new(sha256_fixed_message())
    }
}

impl SpartanCircuit<E> for Sha256Circuit {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(sha256_digest_bits(&self.preimage))
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        _: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }

    // The upstream circuit allocates everything here. The openac-sdk fork's
    // Hyrax prover panics on blind lengths when the precommitted block holds
    // nearly the whole witness, so the gadget runs in `synthesize` instead.
    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        _: &mut CS,
        _: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        let preimage_bits = self
            .preimage
            .iter()
            .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
            .enumerate()
            .map(|(i, b)| {
                AllocatedBit::alloc(cs.namespace(|| format!("preimage bit {i}")), Some(b))
                    .map(Boolean::from)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let hash_bits = sha256(cs.namespace(|| "sha256"), &preimage_bits)?;

        for (i, bit) in hash_bits.iter().enumerate() {
            let n = AllocatedNum::alloc_input(cs.namespace(|| format!("public num {i}")), || {
                Ok(
                    if bit.get_value().ok_or(SynthesisError::AssignmentMissing)? {
                        Scalar::ONE
                    } else {
                        Scalar::ZERO
                    },
                )
            })?;

            cs.enforce(
                || format!("bit == num {i}"),
                |_| bit.lc(CS::one(), Scalar::ONE),
                |lc| lc + CS::one(),
                |lc| lc + n.get_variable(),
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{prove_circuit_in_memory, setup_circuit_keys_no_save};
    use spartan2::traits::snark::R1CSSNARKTrait;

    fn proves_and_verifies(preimage: Vec<u8>) {
        let circuit = Sha256Circuit::new(preimage.clone());
        let (pk, vk) = setup_circuit_keys_no_save(circuit.clone());

        let (proof, _instance, _witness) =
            prove_circuit_in_memory(circuit, &pk).expect("prove failed");
        let public_values = proof.verify(&vk).expect("verify failed");

        assert_eq!(public_values, sha256_digest_bits(&preimage));
    }

    #[test]
    fn proves_and_verifies_short_message() {
        proves_and_verifies(sha256_fixed_message()[..64].to_vec());
    }

    #[test]
    #[ignore = "2 KB setup and prove, slow in debug; run with: cargo test --release -- --ignored fixed_message"]
    fn proves_and_verifies_fixed_message() {
        proves_and_verifies(sha256_fixed_message());
    }
}

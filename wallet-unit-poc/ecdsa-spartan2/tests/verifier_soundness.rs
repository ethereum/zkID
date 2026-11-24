//! Verifier checks on the IPA vectors and on reblinded instances.
//!
//! Uses a tiny cubic circuit, so no compiled Circom artifacts or keys are needed:
//!   cargo test --release --test verifier_soundness

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ecdsa_spartan2::{prove_circuit_in_memory, reblind_in_memory, Scalar, E};
use ff::{derive::rand_core::OsRng, Field};
use serde_json::Value;
use spartan2::{
    traits::{circuit::SpartanCircuit, snark::R1CSSNARKTrait, Engine},
    zk_spartan::R1CSSNARK,
};

#[derive(Clone, Debug, Default)]
struct CubicCircuit;

impl SpartanCircuit<E> for CubicCircuit {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::from(15u64)])
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        _: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }

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
        // x^3 + x + 5 = y with x = 2
        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(Scalar::from(2u64)))?;
        let x_sq = x.square(cs.namespace(|| "x_sq"))?;
        let x_cu = x_sq.mul(cs.namespace(|| "x_cu"), &x)?;
        let y = AllocatedNum::alloc(cs.namespace(|| "y"), || {
            Ok(x_cu.get_value().unwrap() + x.get_value().unwrap() + Scalar::from(5u64))
        })?;
        cs.enforce(
            || "y = x^3 + x + 5",
            |lc| lc + x_cu.get_variable() + x.get_variable() + (Scalar::from(5u64), CS::one()),
            |lc| lc + CS::one(),
            |lc| lc + y.get_variable(),
        );
        let _ = y.inputize(cs.namespace(|| "output"));
        Ok(())
    }
}

type Snark = R1CSSNARK<E>;

fn setup_and_prove() -> (
    <Snark as R1CSSNARKTrait<E>>::ProverKey,
    <Snark as R1CSSNARKTrait<E>>::VerifierKey,
    Snark,
    spartan2::r1cs::SplitR1CSInstance<E>,
    spartan2::r1cs::R1CSWitness<E>,
) {
    let (pk, vk) = Snark::setup(CubicCircuit).unwrap();
    let (proof, instance, witness) = prove_circuit_in_memory(CubicCircuit, &pk).unwrap();
    (pk, vk, proof, instance, witness)
}

// Edits proof.<instance_field>.b_vec through the serde representation.
fn edit_b_vec(proof: &Snark, instance_field: &str, edit: impl FnOnce(&mut Vec<Value>)) -> Snark {
    let mut v = serde_json::to_value(proof).unwrap();
    let b = v[instance_field]["b_vec"].as_array_mut().unwrap();
    edit(b);
    serde_json::from_value(v).unwrap()
}

#[test]
fn honest_proof_verifies() {
    let (_, vk, proof, _, _) = setup_and_prove();
    assert_eq!(proof.verify(&vk).unwrap(), [Scalar::from(15u64)]);
}

// Replaces b with b + w where <z, w> = 0, so <z, b> and the IPA's own check are unchanged.
fn shift_b_keeping_inner_product(proof: &Snark, which: &str) -> Snark {
    let mut v = serde_json::to_value(proof).unwrap();
    let z: Vec<Scalar> =
        serde_json::from_value(v[format!("ipa_proof_{which}")]["z_vec"].clone()).unwrap();
    let inst = format!("ipa_instance_{which}");
    let mut b: Vec<Scalar> = serde_json::from_value(v[&inst]["b_vec"].clone()).unwrap();
    b[0] += z[1];
    b[1] -= z[0];
    v[&inst]["b_vec"] = serde_json::to_value(&b).unwrap();
    serde_json::from_value(v).unwrap()
}

#[test]
fn tampered_b_vec_is_rejected() {
    let (_, vk, proof, _, _) = setup_and_prove();
    for which in ["outer", "inner"] {
        let bad = shift_b_keeping_inner_product(&proof, which);
        assert!(bad.verify(&vk).is_err(), "{which}: altered b_vec accepted");
    }
}

#[test]
fn truncated_b_vec_returns_err() {
    let (_, vk, proof, _, _) = setup_and_prove();
    for field in ["ipa_instance_outer", "ipa_instance_inner"] {
        let bad = edit_b_vec(&proof, field, |b| {
            b.pop();
        });
        assert!(
            bad.verify(&vk).is_err(),
            "{field}: truncated b_vec accepted"
        );
    }
}

#[test]
fn reblinds_share_no_blind_vars() {
    let (pk, vk, proof, instance, witness) = setup_and_prove();
    assert!(
        instance.blind_vars_vals().is_some(),
        "cached instance has blinds"
    );
    let old = instance.blind_vars_vals().unwrap();

    let reblind = || {
        let r: Vec<Scalar> = (0..instance.num_shared_rows())
            .map(|_| Scalar::random(OsRng))
            .collect();
        reblind_in_memory(&pk, instance.clone(), witness.clone(), &r).unwrap()
    };
    let (p1, i1, _) = reblind();
    let (p2, i2, _) = reblind();

    assert_eq!(p1.verify(&vk).unwrap(), [Scalar::from(15u64)]);
    assert_eq!(p2.verify(&vk).unwrap(), [Scalar::from(15u64)]);
    assert!(i1.blind_vars_vals().is_none() && i2.blind_vars_vals().is_none());

    for bytes in [
        bincode::serialize(&i1).unwrap(),
        bincode::serialize(&i2).unwrap(),
        bincode::serialize(&p1).unwrap(),
        bincode::serialize(&p2).unwrap(),
        bincode::serialize(&proof).unwrap(),
    ] {
        for v in old {
            let needle = bincode::serialize(&v).unwrap();
            assert!(!bytes.windows(needle.len()).any(|w| w == needle.as_slice()));
        }
    }
}

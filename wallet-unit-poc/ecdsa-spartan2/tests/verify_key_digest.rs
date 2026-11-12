use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    os::unix::fs::symlink,
    path::{Path, PathBuf},
};

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ecdsa_spartan2::{
    setup::{load_proof, load_verifying_key, save_keys, save_proof},
    E,
};
use ff::Field;
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use spartan2::{
    traits::{circuit::SpartanCircuit, snark::DigestHelperTrait, snark::R1CSSNARKTrait, Engine},
    zk_spartan::R1CSSNARK,
};

type Proof = R1CSSNARK<E>;
type VerifierKey = <Proof as R1CSSNARKTrait<E>>::VerifierKey;

#[derive(Clone, Debug, Default)]
struct CubicCircuit;

impl SpartanCircuit<E> for CubicCircuit {
    fn public_values(&self) -> Result<Vec<<E as Engine>::Scalar>, SynthesisError> {
        Ok(vec![<E as Engine>::Scalar::from(15u64)])
    }

    fn shared<CS: ConstraintSystem<<E as Engine>::Scalar>>(
        &self,
        _: &mut CS,
    ) -> Result<Vec<AllocatedNum<<E as Engine>::Scalar>>, SynthesisError> {
        Ok(vec![])
    }

    fn precommitted<CS: ConstraintSystem<<E as Engine>::Scalar>>(
        &self,
        _: &mut CS,
        _: &[AllocatedNum<<E as Engine>::Scalar>],
    ) -> Result<Vec<AllocatedNum<<E as Engine>::Scalar>>, SynthesisError> {
        Ok(vec![])
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn synthesize<CS: ConstraintSystem<<E as Engine>::Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<<E as Engine>::Scalar>],
        _: &[AllocatedNum<<E as Engine>::Scalar>],
        _: Option<&[<E as Engine>::Scalar]>,
    ) -> Result<(), SynthesisError> {
        // x^3 + x + 5 = y with x = 2
        let one = <E as Engine>::Scalar::ONE;
        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(one + one))?;
        let x_sq = x.square(cs.namespace(|| "x_sq"))?;
        let x_cu = x_sq.mul(cs.namespace(|| "x_cu"), &x)?;
        let y = AllocatedNum::alloc(cs.namespace(|| "y"), || {
            Ok(x_cu.get_value().unwrap()
                + x.get_value().unwrap()
                + <E as Engine>::Scalar::from(5u64))
        })?;

        cs.enforce(
            || "y = x^3 + x + 5",
            |lc| {
                lc + x_cu.get_variable()
                    + x.get_variable()
                    + CS::one()
                    + CS::one()
                    + CS::one()
                    + CS::one()
                    + CS::one()
            },
            |lc| lc + CS::one(),
            |lc| lc + y.get_variable(),
        );

        let _ = y.inputize(cs.namespace(|| "output"));
        Ok(())
    }
}

struct Fixture {
    proof: Proof,
    vk_path: PathBuf,
    sidecar_path: PathBuf,
    pk_digest: [u8; 32],
}

fn tmp_dir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn fixture(name: &str) -> Fixture {
    let dir = tmp_dir(name);
    let circuit = CubicCircuit;
    let (pk, vk) = Proof::setup(circuit.clone()).unwrap();
    let prep = Proof::prep_prove(&pk, circuit.clone(), false).unwrap();
    let proof = Proof::prove(&pk, circuit, &prep, false).unwrap();

    let vk_path = dir.join("tiny_verifying.key");
    save_keys(dir.join("tiny_proving.key"), &vk_path, &pk, &vk).unwrap();
    Fixture {
        proof,
        sidecar_path: vk_path.with_extension("digest"),
        vk_path,
        pk_digest: pk.vk_digest,
    }
}

fn flip_bit(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    bytes[0] ^= 1;
    fs::write(path, bytes).unwrap();
}

/// Flips one bit in a byte near the end of the serialized proof, trying earlier bytes until the
/// result still deserializes. Returns the verify result of the first mutant that does, so a pass
/// means a mutation reached `verify`.
fn verify_mutated_proof(proof_bytes: &[u8], vk: &VerifierKey) -> Result<(), String> {
    for offset in (proof_bytes.len().saturating_sub(256)..proof_bytes.len()).rev() {
        let mut bytes = proof_bytes.to_vec();
        bytes[offset] ^= 1;
        if let Ok(mutant) = bincode::deserialize::<Proof>(&bytes) {
            return mutant.verify(vk).map(|_| ()).map_err(|e| e.to_string());
        }
    }
    panic!("no single-bit mutation of the proof deserialized");
}

#[test]
fn save_keys_writes_sidecar_matching_digest() {
    let f = fixture("sidecar_matches");
    let sidecar = fs::read(&f.sidecar_path).unwrap();
    assert_eq!(sidecar.len(), 32);
    assert_eq!(sidecar, f.pk_digest);
    assert_eq!(
        sidecar,
        Sha3_256::digest(fs::read(&f.vk_path).unwrap()).as_slice()
    );
}

#[test]
fn loaded_key_verifies_proof() {
    let f = fixture("loaded_verifies");
    let vk = load_verifying_key(&f.vk_path).unwrap();
    assert_eq!(
        f.proof.verify(&vk).unwrap(),
        [<E as Engine>::Scalar::from(15u64)]
    );
}

#[test]
fn flipped_sidecar_rejects_proof() {
    let f = fixture("flipped_sidecar");
    flip_bit(&f.sidecar_path);
    let vk = load_verifying_key(&f.vk_path).unwrap();
    assert!(f.proof.verify(&vk).is_err());
}

#[test]
fn missing_sidecar_falls_back_to_lazy_digest() {
    let f = fixture("missing_sidecar");
    fs::remove_file(&f.sidecar_path).unwrap();
    let vk = load_verifying_key(&f.vk_path).unwrap();
    assert_eq!(
        f.proof.verify(&vk).unwrap(),
        [<E as Engine>::Scalar::from(15u64)]
    );
    assert!(!f.sidecar_path.exists(), "load must not write a sidecar");
}

#[test]
fn tampered_proof_is_rejected() {
    let f = fixture("tampered_proof");
    let vk = load_verifying_key(&f.vk_path).unwrap();
    let proof_path = f.vk_path.with_file_name("tiny_proof.bin");
    save_proof(&proof_path, &f.proof).unwrap();
    assert!(load_proof(&proof_path).unwrap().verify(&vk).is_ok());
    assert!(verify_mutated_proof(&fs::read(&proof_path).unwrap(), &vk).is_err());
}

#[test]
fn short_sidecar_is_a_load_error() {
    let f = fixture("short_sidecar");
    fs::write(&f.sidecar_path, &f.pk_digest[..31]).unwrap();
    assert!(load_verifying_key(&f.vk_path).is_err());
}

fn keys_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("keys")
}

fn fixture_path(file: &str) -> PathBuf {
    let path = keys_dir().join(file);
    assert!(
        path.exists(),
        "missing fixture {}: link the v5.0.0 key files into keys/",
        path.display()
    );
    path
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn check_real_key(name: &str, sdk_sha256: &str) {
    let vk_path = fixture_path(&format!("{name}_verifying.key"));
    let pk_path = fixture_path(&format!("{name}_proving.key"));
    let proof_path = fixture_path(&format!("{name}_proof.bin"));

    let vk_bytes = fs::read(&vk_path).unwrap();
    assert_eq!(
        hex(&Sha256::digest(&vk_bytes)),
        sdk_sha256,
        "{name} VK SHA-256 pin"
    );

    let mut pk_file = fs::File::open(&pk_path).unwrap();
    pk_file.seek(SeekFrom::End(-32)).unwrap();
    let mut pk_tail = [0u8; 32];
    pk_file.read_exact(&mut pk_tail).unwrap();

    let file_digest: [u8; 32] = Sha3_256::digest(&vk_bytes).into();
    assert_eq!(file_digest, pk_tail, "{name} SHA3-256(VK file) vs PK tail");

    // Bypasses load_verifying_key so no sidecar is restored: this is the lazy digest.
    let lazy_vk: VerifierKey = bincode::deserialize(&vk_bytes).unwrap();
    assert_eq!(
        lazy_vk.digest().unwrap(),
        pk_tail,
        "{name} lazy digest vs PK tail"
    );

    let dir = tmp_dir(&format!("real_{name}"));
    let linked_vk = dir.join(format!("{name}_verifying.key"));
    symlink(&vk_path, &linked_vk).unwrap();
    let sidecar = linked_vk.with_extension("digest");

    let proof_bytes = fs::read(&proof_path).unwrap();
    let proof: Proof = bincode::deserialize(&proof_bytes).unwrap();

    fs::write(&sidecar, pk_tail).unwrap();
    let vk = load_verifying_key(&linked_vk).unwrap();
    assert!(
        proof.verify(&vk).is_ok(),
        "{name} real proof with correct sidecar"
    );
    assert!(
        verify_mutated_proof(&proof_bytes, &vk).is_err(),
        "{name} tampered proof"
    );

    flip_bit(&sidecar);
    let bad_vk = load_verifying_key(&linked_vk).unwrap();
    assert!(proof.verify(&bad_vk).is_err(), "{name} flipped sidecar");
}

#[test]
#[ignore = "needs v5.0.0 key files in keys/"]
fn real_1k_prepare() {
    check_real_key(
        "1k_prepare",
        "f1fcc1d5036ef6ca9efb538b3510a5a492518018beb217c50ee2c014d7351add",
    );
}

#[test]
#[ignore = "needs v5.0.0 key files in keys/"]
fn real_2k_prepare() {
    check_real_key(
        "2k_prepare",
        "9b45cc7462a236b1056d21c19e1e4dfc2cf52fd20538d43fbe072d9ed106e9d6",
    );
}

#[test]
#[ignore = "needs v5.0.0 key files in keys/"]
fn real_2k_show() {
    check_real_key(
        "2k_show",
        "f0c447a9757d182e8aa23083bc3dba5a9a22f3e0fcbb344724568cc3c83352d8",
    );
}

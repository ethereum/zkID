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

/// Different shape and constants from `CubicCircuit`: y = x^2 + 7 with x = 2.
#[derive(Clone, Debug, Default)]
struct SquareCircuit;

impl SpartanCircuit<E> for SquareCircuit {
    fn public_values(&self) -> Result<Vec<<E as Engine>::Scalar>, SynthesisError> {
        Ok(vec![<E as Engine>::Scalar::from(11u64)])
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
        let two = <E as Engine>::Scalar::from(2u64);
        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(two))?;
        let x_sq = x.square(cs.namespace(|| "x_sq"))?;
        let y = AllocatedNum::alloc(cs.namespace(|| "y"), || {
            Ok(x_sq.get_value().unwrap() + <E as Engine>::Scalar::from(7u64))
        })?;
        cs.enforce(
            || "y = x^2 + 7",
            |lc| lc + x_sq.get_variable() + (<E as Engine>::Scalar::from(7u64), CS::one()),
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
    fixture_for(name, CubicCircuit)
}

fn fixture_for<C: SpartanCircuit<E> + Clone>(name: &str, circuit: C) -> Fixture {
    let dir = tmp_dir(name);
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

fn cubic_out() -> [<E as Engine>::Scalar; 1] {
    [<E as Engine>::Scalar::from(15u64)]
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
    assert_eq!(f.proof.verify(&vk).unwrap(), cubic_out());
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
    assert_eq!(f.proof.verify(&vk).unwrap(), cubic_out());
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

// ---- soundness: a sidecar the attacker controls can only make verification fail ----

fn a_and_b(name: &str) -> (Fixture, Fixture) {
    let a = fixture_for(&format!("{name}_a"), CubicCircuit);
    let b = fixture_for(&format!("{name}_b"), SquareCircuit);
    assert_ne!(a.pk_digest, b.pk_digest, "test circuits must differ");
    (a, b)
}

#[test]
fn proof_for_a_is_rejected_by_key_b_with_its_own_sidecar() {
    let (a, b) = a_and_b("cross_baseline");
    let vk_a = load_verifying_key(&a.vk_path).unwrap();
    let vk_b = load_verifying_key(&b.vk_path).unwrap();
    assert!(a.proof.verify(&vk_a).is_ok());
    assert!(b.proof.verify(&vk_b).is_ok());
    assert!(a.proof.verify(&vk_b).is_err());
    assert!(b.proof.verify(&vk_a).is_err());
}

/// Plants `donor`'s digest next to `key`'s file. Each key must then reject its own proof, which
/// only the digest can cause. The other circuit's proof is rejected on shape alone, so that
/// assertion says nothing about the digest.
#[test]
fn foreign_digest_makes_key_reject_its_own_proof() {
    let (a, b) = a_and_b("foreign_digest");
    for (key, donor) in [(&b, &a), (&a, &b)] {
        fs::write(&key.sidecar_path, donor.pk_digest).unwrap();
        let vk = load_verifying_key(&key.vk_path).unwrap();
        assert_eq!(vk.digest().unwrap(), donor.pk_digest);
        assert!(key.proof.verify(&vk).is_err());
        assert!(donor.proof.verify(&vk).is_err());
    }
}

#[test]
fn all_zero_and_all_ff_sidecars_reject() {
    let (a, b) = a_and_b("zero_ff");
    for fill in [0x00u8, 0xff] {
        for f in [&a, &b] {
            fs::write(&f.sidecar_path, [fill; 32]).unwrap();
            let vk = load_verifying_key(&f.vk_path).unwrap();
            assert!(f.proof.verify(&vk).is_err(), "fill {fill:#x}");
        }
    }
}

// ---- sidecar edge cases ----

#[test]
fn empty_sidecar_is_a_load_error() {
    let f = fixture("empty_sidecar");
    fs::write(&f.sidecar_path, []).unwrap();
    assert!(load_verifying_key(&f.vk_path).is_err());
}

#[test]
fn long_sidecar_is_a_load_error() {
    let f = fixture("long_sidecar");
    let mut bytes = f.pk_digest.to_vec();
    bytes.push(0);
    fs::write(&f.sidecar_path, bytes).unwrap();
    assert!(load_verifying_key(&f.vk_path).is_err());
}

#[test]
fn sidecar_that_is_a_directory_is_a_load_error() {
    let f = fixture("sidecar_dir");
    fs::remove_file(&f.sidecar_path).unwrap();
    fs::create_dir(&f.sidecar_path).unwrap();
    assert!(load_verifying_key(&f.vk_path).is_err());
}

/// `Path::exists` follows symlinks, so a dangling sidecar link reads as "missing" and loading
/// silently falls back to the lazy digest. Pinned as the current behavior.
#[test]
fn dangling_sidecar_symlink_falls_back_silently() {
    let f = fixture("dangling_sidecar");
    fs::remove_file(&f.sidecar_path).unwrap();
    symlink(f.vk_path.with_file_name("does_not_exist"), &f.sidecar_path).unwrap();
    let vk = load_verifying_key(&f.vk_path).expect("dangling link is treated as missing");
    assert_eq!(f.proof.verify(&vk).unwrap(), cubic_out());
}

#[test]
fn sidecar_symlink_to_valid_file_is_followed() {
    let f = fixture("symlinked_sidecar");
    let real = f.vk_path.with_file_name("real.digest");
    fs::rename(&f.sidecar_path, &real).unwrap();
    symlink(&real, &f.sidecar_path).unwrap();
    let vk = load_verifying_key(&f.vk_path).unwrap();
    assert_eq!(vk.digest().unwrap(), f.pk_digest);
}

/// Copies the VK to `name` and plants a wrong sidecar at `sidecar`. Returns whether the wrong
/// digest was consulted, i.e. verification failed.
fn wrong_sidecar_is_consulted(label: &str, name: &str, sidecar: &str) -> bool {
    let f = fixture(label);
    let dir = f.vk_path.parent().unwrap().to_path_buf();
    let vk_path = dir.join(name);
    fs::copy(&f.vk_path, &vk_path).unwrap();
    let mut wrong = f.pk_digest;
    wrong[0] ^= 1;
    fs::write(dir.join(sidecar), wrong).unwrap();
    let vk = load_verifying_key(&vk_path).unwrap();
    f.proof.verify(&vk).is_err()
}

#[test]
fn sidecar_path_for_extensionless_vk_is_name_dot_digest() {
    assert!(wrong_sidecar_is_consulted("ext_none", "foo", "foo.digest"));
    assert!(!wrong_sidecar_is_consulted("ext_none_other", "foo", "foo.key.digest"));
}

#[test]
fn sidecar_path_replaces_only_the_last_extension() {
    assert!(wrong_sidecar_is_consulted("ext_multi", "foo.bar.key", "foo.bar.digest"));
    assert!(!wrong_sidecar_is_consulted("ext_multi_other", "foo.bar.key", "foo.bar.key.digest"));
}

#[test]
fn vk_named_digest_has_sidecar_equal_to_itself() {
    // with_extension("digest") on "x.digest" is "x.digest": the key file would be its own sidecar.
    // Pin that this fails loudly (the key file is not 32 bytes) rather than silently.
    let f = fixture("self_sidecar");
    let path = f.vk_path.with_file_name("x.digest");
    fs::copy(&f.vk_path, &path).unwrap();
    assert!(load_verifying_key(&path).is_err());
}

// ---- round trip ----

#[test]
fn round_trip_preserves_digest_and_resave_is_identical() {
    let dir = tmp_dir("round_trip");
    let (pk, vk) = Proof::setup(CubicCircuit).unwrap();
    let vk_path = dir.join("rt_verifying.key");
    save_keys(dir.join("rt_proving.key"), &vk_path, &pk, &vk).unwrap();
    let sidecar_path = vk_path.with_extension("digest");
    let first_sidecar = fs::read(&sidecar_path).unwrap();
    let first_vk = fs::read(&vk_path).unwrap();

    let loaded = load_verifying_key(&vk_path).unwrap();
    assert_eq!(loaded.digest().unwrap(), vk.digest().unwrap());
    assert_eq!(loaded.digest().unwrap(), pk.vk_digest);

    let dir2 = tmp_dir("round_trip_resave");
    let vk_path2 = dir2.join("rt_verifying.key");
    save_keys(dir2.join("rt_proving.key"), &vk_path2, &pk, &loaded).unwrap();
    assert_eq!(fs::read(vk_path2.with_extension("digest")).unwrap(), first_sidecar);
    assert_eq!(fs::read(&vk_path2).unwrap(), first_vk);
}

#[test]
fn save_keys_twice_overwrites_sidecar() {
    let a = fixture("overwrite");
    let dir = a.vk_path.parent().unwrap().to_path_buf();
    fs::write(&a.sidecar_path, [0xaau8; 32]).unwrap();

    let (pk2, vk2) = Proof::setup(SquareCircuit).unwrap();
    save_keys(dir.join("tiny_proving.key"), &a.vk_path, &pk2, &vk2).unwrap();
    assert_eq!(fs::read(&a.sidecar_path).unwrap(), pk2.vk_digest);

    // Saving the same key again keeps it correct, and the file is not left longer than 32 bytes.
    save_keys(dir.join("tiny_proving.key"), &a.vk_path, &pk2, &vk2).unwrap();
    assert_eq!(fs::read(&a.sidecar_path).unwrap(), pk2.vk_digest);
    let vk = load_verifying_key(&a.vk_path).unwrap();
    assert_eq!(vk.digest().unwrap(), pk2.vk_digest);
}

// ---- mutation coverage ----

/// The proof carries bytes the verifier never reads (the instance's `blind_vars`), so some
/// mutants verify regardless of this change. A restored digest must not change that set: it has
/// to be identical with and without the sidecar.
#[test]
fn restored_digest_does_not_change_which_mutants_verify() {
    let f = fixture("mutation_differential");
    let restored = load_verifying_key(&f.vk_path).unwrap();
    let lazy: VerifierKey = bincode::deserialize(&fs::read(&f.vk_path).unwrap()).unwrap();
    let bytes = bincode::serialize(&f.proof).unwrap();

    let step = (bytes.len() / 200).max(1);
    let mut reached = 0;
    for offset in (0..bytes.len()).step_by(step) {
        let mut mutated = bytes.clone();
        mutated[offset] ^= 1 << (offset % 8);
        if let Ok(mutant) = bincode::deserialize::<Proof>(&mutated) {
            reached += 1;
            let with_sidecar = mutant.verify(&restored).is_ok();
            let without = mutant.verify(&lazy).is_ok();
            assert_eq!(with_sidecar, without, "offset {offset}");
        }
    }
    assert!(reached > 0);
}

// ---- fork level: the digest is not part of the serialized key ----

#[test]
fn restoring_a_digest_does_not_change_key_bytes() {
    let f = fixture("serialize_same");
    let original = fs::read(&f.vk_path).unwrap();
    let lazy: VerifierKey = bincode::deserialize(&original).unwrap();

    lazy.restore_digest_unchecked(f.pk_digest).unwrap();
    assert_eq!(bincode::serialize(&lazy).unwrap(), original);

    let mut wrong = f.pk_digest;
    wrong[31] ^= 0x80;
    let wrong_key: VerifierKey = bincode::deserialize(&original).unwrap();
    wrong_key.restore_digest_unchecked(wrong).unwrap();
    assert_eq!(bincode::serialize(&wrong_key).unwrap(), original);
    assert_eq!(wrong_key.digest().unwrap(), wrong);
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

/// The last 32 bytes of a proving key are the SHA3-256 digest of its verifying key.
fn pk_tail(pk_path: &Path) -> [u8; 32] {
    let mut pk_file = fs::File::open(pk_path).unwrap();
    pk_file.seek(SeekFrom::End(-32)).unwrap();
    let mut tail = [0u8; 32];
    pk_file.read_exact(&mut tail).unwrap();
    tail
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

    let tail = pk_tail(&pk_path);

    let file_digest: [u8; 32] = Sha3_256::digest(&vk_bytes).into();
    assert_eq!(file_digest, tail, "{name} SHA3-256(VK file) vs PK tail");

    // Bypasses load_verifying_key so no sidecar is restored: this is the lazy digest.
    let lazy_vk: VerifierKey = bincode::deserialize(&vk_bytes).unwrap();
    assert_eq!(
        lazy_vk.digest().unwrap(),
        tail,
        "{name} lazy digest vs PK tail"
    );

    let dir = tmp_dir(&format!("real_{name}"));
    let linked_vk = dir.join(format!("{name}_verifying.key"));
    symlink(&vk_path, &linked_vk).unwrap();
    let sidecar = linked_vk.with_extension("digest");

    let proof_bytes = fs::read(&proof_path).unwrap();
    let proof: Proof = bincode::deserialize(&proof_bytes).unwrap();

    fs::write(&sidecar, tail).unwrap();
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

/// Loads `vk_name`'s key with the digest sidecar of `digest_from`, then checks each proof is
/// rejected. A proof of a circuit other than `vk_name` is rejected on shape alone.
fn real_cross(vk_name: &str, digest_from: &str, proof_names: &[&str]) {
    let vk_path = fixture_path(&format!("{vk_name}_verifying.key"));
    let foreign = pk_tail(&fixture_path(&format!("{digest_from}_proving.key")));

    let dir = tmp_dir(&format!("real_cross_{vk_name}_with_{digest_from}"));
    let linked = dir.join(format!("{vk_name}_verifying.key"));
    symlink(&vk_path, &linked).unwrap();
    fs::write(linked.with_extension("digest"), foreign).unwrap();
    let vk = load_verifying_key(&linked).unwrap();
    assert_eq!(vk.digest().unwrap(), foreign);

    for proof_name in proof_names {
        let proof: Proof =
            bincode::deserialize(&fs::read(fixture_path(&format!("{proof_name}_proof.bin"))).unwrap())
                .unwrap();
        assert!(
            proof.verify(&vk).is_err(),
            "{proof_name} proof accepted by {vk_name} key with {digest_from} digest"
        );
    }
}

#[test]
#[ignore = "needs v5.0.0 key files in keys/"]
fn real_2k_show_key_with_prepare_digest_rejects() {
    real_cross("2k_show", "2k_prepare", &["2k_prepare", "2k_show"]);
}

#[test]
#[ignore = "needs v5.0.0 key files in keys/"]
fn real_2k_prepare_key_with_show_digest_rejects() {
    real_cross("2k_prepare", "2k_show", &["2k_show", "2k_prepare"]);
}

#[test]
#[ignore = "needs v5.0.0 key files in keys/"]
fn real_proof_of_other_circuit_rejects_under_correct_digest() {
    for (vk_name, proof_name) in [("2k_show", "2k_prepare"), ("2k_prepare", "2k_show")] {
        real_cross(vk_name, vk_name, &[proof_name]);
    }
}

// ---- interrupted saves: the sidecar is absent or matches the key file ----

fn dir_entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn save_keys_leaves_no_temporary_file() {
    let f = fixture("no_temp_file");
    let dir = f.vk_path.parent().unwrap().to_path_buf();
    assert_eq!(
        dir_entries(&dir),
        ["tiny_proving.key", "tiny_verifying.digest", "tiny_verifying.key"]
    );

    let (pk2, vk2) = Proof::setup(SquareCircuit).unwrap();
    save_keys(dir.join("tiny_proving.key"), &f.vk_path, &pk2, &vk2).unwrap();
    assert_eq!(
        dir_entries(&dir),
        ["tiny_proving.key", "tiny_verifying.digest", "tiny_verifying.key"]
    );
}

/// The state the save ordering leaves after a crash between the VK write and the sidecar rename:
/// key B's file, no sidecar.
#[test]
fn key_replaced_without_sidecar_verifies_lazily() {
    let (a, b) = a_and_b("crash_state");
    fs::copy(&b.vk_path, &a.vk_path).unwrap();
    fs::remove_file(&a.sidecar_path).unwrap();
    let vk = load_verifying_key(&a.vk_path).unwrap();
    assert!(b.proof.verify(&vk).is_ok());
    assert!(a.proof.verify(&vk).is_err());
}

/// A save that fails at the VK file (here: a directory sits in its place) must not leave the
/// previous key's sidecar behind.
#[test]
fn failed_vk_write_removes_the_old_sidecar() {
    let f = fixture("failed_vk_write");
    let dir = f.vk_path.parent().unwrap().to_path_buf();
    fs::remove_file(&f.vk_path).unwrap();
    fs::create_dir(&f.vk_path).unwrap();
    assert!(f.sidecar_path.exists());

    let (pk2, vk2) = Proof::setup(SquareCircuit).unwrap();
    assert!(save_keys(dir.join("tiny_proving.key"), &f.vk_path, &pk2, &vk2).is_err());
    assert!(!f.sidecar_path.exists());
}

/// A sidecar that cannot be removed fails the save before the VK file is touched.
#[test]
fn unremovable_sidecar_fails_before_the_vk_is_rewritten() {
    let f = fixture("unremovable_sidecar");
    let dir = f.vk_path.parent().unwrap().to_path_buf();
    let before = fs::read(&f.vk_path).unwrap();
    fs::remove_file(&f.sidecar_path).unwrap();
    fs::create_dir(&f.sidecar_path).unwrap();

    let (pk2, vk2) = Proof::setup(SquareCircuit).unwrap();
    assert!(save_keys(dir.join("tiny_proving.key"), &f.vk_path, &pk2, &vk2).is_err());
    assert_eq!(fs::read(&f.vk_path).unwrap(), before);
}

/// The VK is rewritten and then the sidecar step fails (a directory sits at the temporary
/// sidecar path): the sidecar must be absent and the new key must verify lazily.
#[test]
fn failed_sidecar_write_after_vk_rewrite_leaves_no_sidecar() {
    let a = fixture("failed_sidecar_write");
    let dir = a.vk_path.parent().unwrap().to_path_buf();
    fs::create_dir(a.sidecar_path.with_extension("digest.tmp")).unwrap();

    let (pk_b, vk_b) = Proof::setup(SquareCircuit).unwrap();
    let prep = Proof::prep_prove(&pk_b, SquareCircuit, false).unwrap();
    let proof_b = Proof::prove(&pk_b, SquareCircuit, &prep, false).unwrap();
    assert!(save_keys(dir.join("tiny_proving.key"), &a.vk_path, &pk_b, &vk_b).is_err());

    assert!(!a.sidecar_path.exists());
    let vk = load_verifying_key(&a.vk_path).unwrap();
    assert!(proof_b.verify(&vk).is_ok());
    assert!(a.proof.verify(&vk).is_err());
}

/// The PK is the largest file and the likeliest to hit a full disk. A failure there must leave
/// the VK and its still-valid sidecar alone.
#[test]
fn failed_pk_write_leaves_vk_and_sidecar_untouched() {
    let a = fixture("failed_pk_write");
    let dir = a.vk_path.parent().unwrap().to_path_buf();
    let pk_path = dir.join("tiny_proving.key");
    fs::remove_file(&pk_path).unwrap();
    fs::create_dir(&pk_path).unwrap();
    let vk_before = fs::read(&a.vk_path).unwrap();

    let (pk_b, vk_b) = Proof::setup(SquareCircuit).unwrap();
    assert!(save_keys(&pk_path, &a.vk_path, &pk_b, &vk_b).is_err());

    assert_eq!(fs::read(&a.vk_path).unwrap(), vk_before);
    assert_eq!(fs::read(&a.sidecar_path).unwrap(), a.pk_digest);
    let vk = load_verifying_key(&a.vk_path).unwrap();
    assert!(a.proof.verify(&vk).is_ok());
}

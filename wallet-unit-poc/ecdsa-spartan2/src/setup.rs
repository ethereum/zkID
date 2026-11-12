#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;
use std::{
    fs::{create_dir_all, remove_file, rename, File},
    io::{BufReader, Cursor, Write},
    path::Path,
};

use spartan2::{
    r1cs::{R1CSWitness, SplitR1CSInstance},
    traits::{
        circuit::SpartanCircuit,
        snark::{DigestHelperTrait, R1CSSNARKTrait},
        Engine,
    },
    zk_spartan::R1CSSNARK,
};
use tracing::info;

use crate::E;
use memmap2::MmapOptions;

// Re-export key constants from paths module for convenience
pub use crate::paths::keys::*;

pub fn save_keys(
    pk_path: impl AsRef<Path>,
    vk_path: impl AsRef<Path>,
    pk: &<R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey,
    vk: &<R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let pk_path = pk_path.as_ref();
    let vk_path = vk_path.as_ref();

    if let Some(parent) = pk_path.parent() {
        create_dir_all(parent)?;
    }
    if let Some(parent) = vk_path.parent() {
        create_dir_all(parent)?;
    }

    // The sidecar on disk is either absent (loads fall back to the lazy digest) or matches the VK
    // file: it is removed before the VK is touched and renamed into place only after the VK is
    // written, so a crash or error in between never pairs a key with the previous key's digest.
    // Concurrent saves to the same path are not covered.
    let digest = vk.digest()?;
    let digest_path = vk_path.with_extension("digest");
    match remove_file(&digest_path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
        _ => {}
    }

    let pk_bytes = bincode::serialize(pk)?;
    let mut pk_file = File::create(pk_path)?;
    pk_file.write_all(&pk_bytes)?;

    info!("Saved ZK-Spartan proving key to: {}", pk_path.display());

    let vk_bytes = bincode::serialize(vk)?;
    let mut vk_file = File::create(vk_path)?;
    vk_file.write_all(&vk_bytes)?;
    info!("Saved ZK-Spartan verifying key to: {}", vk_path.display());

    let tmp_path = digest_path.with_extension("digest.tmp");
    File::create(&tmp_path)?.write_all(&digest)?;
    rename(&tmp_path, &digest_path)?;
    info!(
        "Saved ZK-Spartan verifying key digest to: {}",
        digest_path.display()
    );

    Ok(())
}

#[allow(dead_code)]
pub fn load_keys(
    pk_path: impl AsRef<Path>,
    vk_path: impl AsRef<Path>,
) -> Result<
    (
        <R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey,
        <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey,
    ),
    Box<dyn std::error::Error>,
> {
    let pk_path = pk_path.as_ref();
    let vk_path = vk_path.as_ref();

    let pk_file = File::open(pk_path)?;
    let pk = bincode::deserialize_from(&mut BufReader::new(pk_file))?;

    info!("Loaded ZK-Spartan proving key from: {}", pk_path.display());

    let vk_file = File::open(vk_path)?;
    let vk = bincode::deserialize_from(&mut BufReader::new(vk_file))?;
    info!(
        "Loaded ZK-Spartan verifying key from: {}",
        vk_path.display()
    );

    Ok((pk, vk))
}

pub fn load_proving_key(
    pk_path: impl AsRef<Path>,
) -> Result<<R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey, Box<dyn std::error::Error>> {
    let pk_file = File::open(pk_path.as_ref())?;
    let pk_mmap = unsafe { MmapOptions::new().map(&pk_file)? };
    let pk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey =
        bincode::deserialize_from(Cursor::new(&pk_mmap[..]))?;
    Ok(pk)
}

pub fn load_verifying_key(
    vk_path: impl AsRef<Path>,
) -> Result<<R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey, Box<dyn std::error::Error>> {
    let vk_path = vk_path.as_ref();
    let vk_file = File::open(vk_path)?;
    let vk_mmap = unsafe { MmapOptions::new().map(&vk_file)? };
    let vk: <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey =
        bincode::deserialize_from(Cursor::new(&vk_mmap[..]))?;

    // Trusted like the key file itself: a wrong value only makes honest proofs fail to verify.
    let digest_path = vk_path.with_extension("digest");
    if digest_path.exists() {
        let digest: [u8; 32] = std::fs::read(&digest_path)?.try_into().map_err(|_| {
            format!(
                "verifying key digest {} must be exactly 32 bytes",
                digest_path.display()
            )
        })?;
        vk.restore_digest_unchecked(digest)?;
        info!(
            "Restored verifying key digest from: {}",
            digest_path.display()
        );
    }
    Ok(vk)
}

pub fn save_shared_blinds<E: Engine>(
    shared_blinds_path: impl AsRef<Path>,
    shared_blinds: &[E::Scalar],
) -> Result<(), Box<dyn std::error::Error>> {
    let shared_blinds_path = shared_blinds_path.as_ref();
    if let Some(parent) = shared_blinds_path.parent() {
        create_dir_all(parent)?;
    }

    let shared_blinds_bytes = bincode::serialize(shared_blinds)?;
    let mut shared_blinds_file = File::create(shared_blinds_path)?;
    shared_blinds_file.write_all(&shared_blinds_bytes)?;
    info!(
        "Saved ZK-Spartan shared_blinds to: {}",
        shared_blinds_path.display()
    );

    Ok(())
}

pub fn save_proof(
    proof_path: impl AsRef<Path>,
    proof: &R1CSSNARK<E>,
) -> Result<(), Box<dyn std::error::Error>> {
    let proof_path = proof_path.as_ref();
    if let Some(parent) = proof_path.parent() {
        create_dir_all(parent)?;
    }

    let proof_bytes = bincode::serialize(proof)?;
    let mut proof_file = File::create(proof_path)?;
    proof_file.write_all(&proof_bytes)?;
    info!("Saved ZK-Spartan proof to: {}", proof_path.display());

    Ok(())
}

pub fn save_instance(
    instance_path: impl AsRef<Path>,
    instance: &SplitR1CSInstance<E>,
) -> Result<(), Box<dyn std::error::Error>> {
    let instance_path = instance_path.as_ref();
    if let Some(parent) = instance_path.parent() {
        create_dir_all(parent)?;
    }

    let instance_bytes = bincode::serialize(instance)?;
    let mut instance_file = File::create(instance_path)?;
    instance_file.write_all(&instance_bytes)?;
    info!("Saved ZK-Spartan instance to: {}", instance_path.display());

    Ok(())
}

pub fn save_witness(
    witness_path: impl AsRef<Path>,
    witness: &R1CSWitness<E>,
) -> Result<(), Box<dyn std::error::Error>> {
    let witness_path = witness_path.as_ref();
    if let Some(parent) = witness_path.parent() {
        create_dir_all(parent)?;
    }

    let witness_bytes = bincode::serialize(witness)?;
    let mut witness_file = File::create(witness_path)?;
    witness_file.write_all(&witness_bytes)?;
    info!("Saved ZK-Spartan witness to: {}", witness_path.display());

    Ok(())
}

pub fn load_shared_blinds<E: Engine>(
    shared_blinds_path: impl AsRef<Path>,
) -> Result<Vec<E::Scalar>, Box<dyn std::error::Error>> {
    let shared_blinds_path = shared_blinds_path.as_ref();
    let shared_blinds_file = File::open(shared_blinds_path)?;
    let shared_blinds: Vec<E::Scalar> =
        bincode::deserialize_from(&mut BufReader::new(shared_blinds_file))?;
    info!(
        "Loaded ZK-Spartan shared_blinds from: {}",
        shared_blinds_path.display()
    );
    Ok(shared_blinds)
}

pub fn load_proof(
    proof_path: impl AsRef<Path>,
) -> Result<R1CSSNARK<E>, Box<dyn std::error::Error>> {
    let proof_path = proof_path.as_ref();
    let proof_file = File::open(proof_path)?;
    let proof: R1CSSNARK<E> = bincode::deserialize_from(&mut BufReader::new(proof_file))?;
    info!("Loaded ZK-Spartan proof from: {}", proof_path.display());
    Ok(proof)
}

pub fn load_instance(
    instance_path: impl AsRef<Path>,
) -> Result<SplitR1CSInstance<E>, Box<dyn std::error::Error>> {
    let instance_path = instance_path.as_ref();
    let instance_file = File::open(instance_path)?;
    let instance: SplitR1CSInstance<E> =
        bincode::deserialize_from(&mut BufReader::new(instance_file))?;
    info!(
        "Loaded ZK-Spartan instance from: {}",
        instance_path.display()
    );
    Ok(instance)
}

pub fn load_witness(
    witness_path: impl AsRef<Path>,
) -> Result<R1CSWitness<E>, Box<dyn std::error::Error>> {
    let witness_path = witness_path.as_ref();
    let witness_file = File::open(witness_path)?;
    let witness: R1CSWitness<E> = bincode::deserialize_from(&mut BufReader::new(witness_file))?;
    info!("Loaded ZK-Spartan witness from: {}", witness_path.display());
    Ok(witness)
}

pub fn setup_circuit_keys<C: SpartanCircuit<E> + Clone + std::fmt::Debug>(
    circuit: C,
    pk_path: impl AsRef<Path>,
    vk_path: impl AsRef<Path>,
) {
    let pk_path = pk_path.as_ref();
    let vk_path = vk_path.as_ref();

    #[cfg(not(target_arch = "wasm32"))]
    let t0 = Instant::now();

    let (pk, vk) = R1CSSNARK::<E>::setup(circuit.clone()).expect("setup failed");

    #[cfg(not(target_arch = "wasm32"))]
    {
        let setup_ms = t0.elapsed().as_millis();
        info!(
            elapsed_ms = setup_ms,
            "Setup completed (~{:.1}s)",
            setup_ms as f64 / 1000.0
        );
    }

    if let Err(e) = save_keys(pk_path, vk_path, &pk, &vk) {
        eprintln!("Failed to save keys: {}", e);
        std::process::exit(1);
    }

    info!("Keys generated and saved successfully!");
    info!("Proving key: {}", pk_path.display());
    info!("Verifying key: {}", vk_path.display());
}

/// Setup circuit keys without saving to file - useful for benchmarking
/// Returns the proving and verifying keys
pub fn setup_circuit_keys_no_save<C: SpartanCircuit<E> + Clone + std::fmt::Debug>(
    circuit: C,
) -> (
    <R1CSSNARK<E> as R1CSSNARKTrait<E>>::ProverKey,
    <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey,
) {
    R1CSSNARK::<E>::setup(circuit.clone()).expect("setup failed")
}

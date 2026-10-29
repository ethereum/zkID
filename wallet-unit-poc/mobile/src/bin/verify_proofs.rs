//! usage: verify_proofs <proofs_dir> <vk_dir>
//!
//! Verifies the `*.proof` files in `proofs_dir` against the pinned verifying keys
//! and prints PASS or FAIL per check. `prepare.proof` and `show.proof` are checked
//! on their own; `present_prepare.proof` and `present_show.proof` are checked as a
//! pair, which also requires them to commit to the same shared witness (as
//! `verify_presentation` does). `sha256.proof` must also expose the digest of
//! the benchmark's fixed 2 KB message. Exits non-zero on any failure or when no proof is
//! found. Prepare vks are ~430 MB, so this runs on the host, never the phone.
use ecdsa_spartan2::{
    circuits::sha256_circuit::{sha256_digest_bits, sha256_fixed_message},
    load_proof, load_verifying_key,
    prover::verify_linked,
    E,
};
use spartan2::{traits::snark::R1CSSNARKTrait, zk_spartan::R1CSSNARK};
use std::path::{Path, PathBuf};

const PREPARE_VK: &str = "2k_prepare_verifying.key";
const SHOW_VK: &str = "2k_show_verifying.key";
const SHA256_VK: &str = "sha256_2048_verifying.key";

#[derive(Debug, PartialEq)]
enum Check {
    Single { stem: &'static str, vk: &'static str },
    Linked,
    Failed(String),
}

/// Which checks the proofs present call for. A present proof without its partner
/// is a failure, since half a presentation proves nothing about linkage.
fn plan(stems: &[String]) -> Vec<Check> {
    let has = |s: &str| stems.iter().any(|x| x == s);
    let mut checks = Vec::new();
    if has("prepare") {
        checks.push(Check::Single { stem: "prepare", vk: PREPARE_VK });
    }
    if has("show") {
        checks.push(Check::Single { stem: "show", vk: SHOW_VK });
    }
    if has("sha256") {
        checks.push(Check::Single { stem: "sha256", vk: SHA256_VK });
    }
    match (has("present_prepare"), has("present_show")) {
        (true, true) => checks.push(Check::Linked),
        (true, false) => checks.push(Check::Failed("present_prepare.proof has no present_show.proof".into())),
        (false, true) => checks.push(Check::Failed("present_show.proof has no present_prepare.proof".into())),
        (false, false) => {}
    }
    for s in stems {
        if !["prepare", "show", "sha256", "present_prepare", "present_show"].contains(&s.as_str()) {
            checks.push(Check::Failed(format!("{s}.proof: unknown proof name")));
        }
    }
    checks
}

type Vk = <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey;

/// Loads each verifying key at most once.
struct Keys {
    dir: PathBuf,
    prepare: Option<Vk>,
    show: Option<Vk>,
    sha256: Option<Vk>,
}

impl Keys {
    fn get(&mut self, name: &str) -> Result<&Vk, String> {
        let slot = match name {
            PREPARE_VK => &mut self.prepare,
            SHOW_VK => &mut self.show,
            SHA256_VK => &mut self.sha256,
            _ => return Err(format!("unknown verifying key {name}")),
        };
        if slot.is_none() {
            *slot = Some(load_verifying_key(self.dir.join(name)).map_err(|e| format!("load vk {name}: {e}"))?);
        }
        Ok(slot.as_ref().unwrap())
    }
}

fn load(dir: &Path, stem: &str) -> Result<R1CSSNARK<E>, String> {
    load_proof(dir.join(format!("{stem}.proof"))).map_err(|e| format!("load {stem}.proof: {e}"))
}

fn run_check(check: &Check, dir: &Path, keys: &mut Keys) -> (String, Result<(), String>) {
    match check {
        Check::Single { stem, vk } => {
            let result = load(dir, stem).and_then(|proof| {
                let vk = keys.get(vk)?;
                let public_values = proof.verify(vk).map_err(|e| format!("verify: {e:?}"))?;
                if *stem == "sha256" && public_values != sha256_digest_bits(&sha256_fixed_message()) {
                    return Err("public values are not the SHA-256 of the fixed message".into());
                }
                Ok(())
            });
            (format!("{stem}.proof"), result)
        }
        Check::Linked => {
            let label = "present_prepare.proof + present_show.proof (linked)".to_string();
            let result = (|| {
                let prepare = load(dir, "present_prepare")?;
                let show = load(dir, "present_show")?;
                keys.get(PREPARE_VK)?;
                keys.get(SHOW_VK)?;
                let (pvk, svk) = (keys.prepare.as_ref().unwrap(), keys.show.as_ref().unwrap());
                verify_linked(&prepare, pvk, &show, svk)
                    .map(|_| ())
                    .ok_or_else(|| "a proof is invalid or they do not share comm_W_shared".to_string())
            })();
            (label, result)
        }
        Check::Failed(why) => (why.clone(), Err("unusable".into())),
    }
}

fn run() -> bool {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: verify_proofs <proofs_dir> <vk_dir>");
        return false;
    }
    let (dir, vks) = (PathBuf::from(&args[1]), PathBuf::from(&args[2]));
    let mut stems: Vec<String> = std::fs::read_dir(&dir)
        .expect("read proofs dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "proof"))
        .filter_map(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()))
        .collect();
    stems.sort();
    if stems.is_empty() {
        eprintln!("no .proof files in {}", dir.display());
        return false;
    }
    let mut keys = Keys { dir: vks, prepare: None, show: None, sha256: None };
    let mut all_ok = true;
    for check in plan(&stems) {
        let (label, result) = run_check(&check, &dir, &mut keys);
        match (&check, &result) {
            (_, Ok(())) => println!("PASS {label}"),
            (Check::Failed(_), _) => println!("FAIL {label}"),
            (_, Err(e)) => println!("FAIL {label}: {e}"),
        }
        all_ok &= result.is_ok();
    }
    all_ok
}

fn main() {
    // Verification recurses deeply; the default main-thread stack overflows.
    let ok = std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(run)
        .unwrap()
        .join()
        .unwrap();
    std::process::exit(if ok { 0 } else { 1 });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stems(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn present_pair_is_checked_as_linked() {
        assert_eq!(plan(&stems(&["present_prepare", "present_show"])), vec![Check::Linked]);
    }

    #[test]
    fn single_runs_use_their_own_vk() {
        assert_eq!(
            plan(&stems(&["prepare", "show"])),
            vec![
                Check::Single { stem: "prepare", vk: PREPARE_VK },
                Check::Single { stem: "show", vk: SHOW_VK }
            ]
        );
    }

    #[test]
    fn sha256_uses_its_own_vk() {
        assert_eq!(
            plan(&stems(&["sha256"])),
            vec![Check::Single { stem: "sha256", vk: SHA256_VK }]
        );
    }

    #[test]
    fn unknown_vk_name_is_an_error() {
        let mut keys = Keys { dir: PathBuf::from("/nonexistent"), prepare: None, show: None, sha256: None };
        assert!(keys.get("mystery.key").err().unwrap().contains("unknown verifying key"));
    }

    #[test]
    fn half_a_presentation_fails() {
        assert!(matches!(plan(&stems(&["present_show"]))[0], Check::Failed(_)));
        assert!(matches!(plan(&stems(&["present_prepare"]))[0], Check::Failed(_)));
    }

    #[test]
    fn unknown_names_fail() {
        assert!(matches!(plan(&stems(&["mystery"]))[0], Check::Failed(_)));
    }
}

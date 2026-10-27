//! usage: verify_proofs <proofs_dir> <vk_dir>
//!
//! Verifies every `*.proof` in `proofs_dir` against the pinned verifying key and
//! prints PASS or FAIL per file. Exits non-zero on any failure or when no proof
//! is found. Prepare vks are ~430 MB, so this runs on the host, never the phone.
use ecdsa_spartan2::{load_proof, load_verifying_key};
use spartan2::traits::snark::R1CSSNARKTrait;
use std::path::PathBuf;

fn vk_name(stem: &str) -> Option<&'static str> {
    match stem {
        "prepare" | "present_prepare" => Some("2k_prepare_verifying.key"),
        "show" | "present_show" => Some("2k_show_verifying.key"),
        _ => None,
    }
}

fn run() -> bool {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: verify_proofs <proofs_dir> <vk_dir>");
        return false;
    }
    let (dir, vks) = (PathBuf::from(&args[1]), PathBuf::from(&args[2]));
    let mut proofs: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("read proofs dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "proof"))
        .collect();
    proofs.sort();
    if proofs.is_empty() {
        eprintln!("no .proof files in {}", dir.display());
        return false;
    }
    let mut all_ok = true;
    for path in proofs {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
        let ok = match vk_name(&stem) {
            None => {
                println!("FAIL {name}: unknown proof name");
                false
            }
            Some(vk) => {
                let result = load_proof(&path)
                    .map_err(|e| format!("load proof: {e}"))
                    .and_then(|proof| {
                        let vk = load_verifying_key(vks.join(vk)).map_err(|e| format!("load vk: {e}"))?;
                        proof.verify(&vk).map(|_| ()).map_err(|e| format!("verify: {e:?}"))
                    });
                match &result {
                    Ok(()) => println!("PASS {name}"),
                    Err(e) => println!("FAIL {name}: {e}"),
                }
                result.is_ok()
            }
        };
        all_ok &= ok;
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

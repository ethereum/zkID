//! Splits standalone verification into its stages (issue #38).
//!
//! Usage: bench_verify <vk_path> <proof_path> [runs]

use std::{
    env,
    fs::{self, File},
    io::{BufReader, Cursor},
    time::Instant,
};

use ecdsa_spartan2::{load_proof, Scalar, E};
use ff::Field;
use memmap2::MmapOptions;
use serde::Deserialize;
use spartan2::{
    traits::{
        pcs::PCSEngineTrait,
        snark::{DigestHelperTrait, R1CSSNARKTrait},
        Engine,
    },
    zk_spartan::R1CSSNARK,
};

type Vk = <R1CSSNARK<E> as R1CSSNARKTrait<E>>::VerifierKey;

// Field-for-field mirrors of spartan2's private key layout, used only to read
// matrix statistics out of the same bincode bytes.
#[derive(Deserialize)]
struct SparseMirror {
    data: Vec<Scalar>,
    indices: Vec<usize>,
    indptr: Vec<usize>,
    cols: usize,
}

#[derive(Deserialize)]
struct ShapeMirror {
    sizes: [usize; 10],
    a: SparseMirror,
    b: SparseMirror,
    c: SparseMirror,
}

#[derive(Deserialize)]
struct VkMirror {
    _vk_ee: <<E as Engine>::PCS as PCSEngineTrait<E>>::VerifierKey,
    shape: ShapeMirror,
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e3
}

fn report(label: &str, samples: &mut [f64]) {
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!(
        "{label:<34} min {:>9.1} ms   median {:>9.1} ms",
        samples[0],
        samples[samples.len() / 2]
    );
}

fn matrix_stats(name: &str, m: &SparseMirror) {
    let nnz = m.data.len();
    let one = m.data.iter().filter(|v| **v == Scalar::ONE).count();
    let neg_one = m.data.iter().filter(|v| **v == -Scalar::ONE).count();
    let small = m
        .data
        .iter()
        .filter(|v| {
            let bytes = bincode::serialize(*v).unwrap();
            bytes[8..].iter().all(|b| *b == 0)
        })
        .count();
    let max_col = m.indices.iter().copied().max().unwrap_or(0);
    println!(
        "{name}: nnz {nnz}, rows {}, cols {}, max col {max_col}, +1 {:.1}%, -1 {:.1}%, fits u64 {:.1}%",
        m.indptr.len() - 1,
        m.cols,
        100.0 * one as f64 / nnz as f64,
        100.0 * neg_one as f64 / nnz as f64,
        100.0 * small as f64 / nnz as f64,
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let vk_path = &args[1];
    let proof_path = &args[2];
    let runs: usize = args.get(3).map_or(5, |s| s.parse().unwrap());

    let proof = load_proof(proof_path).expect("load proof");
    println!(
        "vk {} ({:.1} MB), {} runs, {} threads",
        vk_path,
        fs::metadata(vk_path).unwrap().len() as f64 / 1e6,
        runs,
        std::thread::available_parallelism().unwrap()
    );

    let (mut mmap_load, mut read, mut deser, mut bufread) = (vec![], vec![], vec![], vec![]);
    let (mut digest, mut first_verify, mut warm_verify) = (vec![], vec![], vec![]);

    for _ in 0..runs {
        let t = Instant::now();
        let file = File::open(vk_path).unwrap();
        let mmap = unsafe { MmapOptions::new().map(&file).unwrap() };
        let vk: Vk = bincode::deserialize_from(Cursor::new(&mmap[..])).unwrap();
        mmap_load.push(ms(t));
        drop(mmap);

        let t = Instant::now();
        proof.verify(&vk).expect("verify");
        first_verify.push(ms(t));

        let t = Instant::now();
        proof.verify(&vk).expect("verify");
        warm_verify.push(ms(t));
        drop(vk);

        let t = Instant::now();
        let bytes = fs::read(vk_path).unwrap();
        read.push(ms(t));
        let t = Instant::now();
        let vk: Vk = bincode::deserialize(&bytes).unwrap();
        deser.push(ms(t));
        drop(bytes);

        let t = Instant::now();
        vk.digest().unwrap();
        digest.push(ms(t));
        drop(vk);

        let t = Instant::now();
        let vk: Vk =
            bincode::deserialize_from(BufReader::with_capacity(1 << 20, File::open(vk_path).unwrap()))
                .unwrap();
        bufread.push(ms(t));
        drop(vk);
    }

    report("load: mmap + deserialize (current)", &mut mmap_load);
    report("load: fs::read", &mut read);
    report("load: deserialize from bytes", &mut deser);
    report("load: BufReader + deserialize", &mut bufread);
    report("vk.digest() on a fresh key", &mut digest);
    report("verify, first call on a fresh key", &mut first_verify);
    report("verify, digest cached", &mut warm_verify);

    let mirror: VkMirror = bincode::deserialize(&fs::read(vk_path).unwrap()).unwrap();
    println!("shape sizes {:?}", mirror.shape.sizes);
    matrix_stats("A", &mirror.shape.a);
    matrix_stats("B", &mirror.shape.b);
    matrix_stats("C", &mirror.shape.c);
}

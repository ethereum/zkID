fn main() {
    // Construct absolute path to circuits using CARGO_MANIFEST_DIR
    // This ensures the path resolves correctly regardless of working directory
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let circuits_dir = std::path::PathBuf::from(&manifest_dir)
        .parent() // Go up from ecdsa-spartan2/ to wallet-unit-poc/
        .expect("Failed to get parent directory")
        .join("circom/build/cpp");

    // Emit cfg flags for each JWT circuit size variant that has been compiled.
    // The witness!() macro in prepare_circuit.rs uses these flags to conditionally
    // include the witness-generation function for each compiled size.
    for size in ["1k", "2k", "4k", "8k"] {
        // Declare the cfg key so rustc doesn't warn about unknown cfg names.
        println!("cargo::rustc-check-cfg=cfg(has_circuit_{})", size);

        let cpp_file = circuits_dir.join(format!("jwt_{}.cpp", size));
        if cpp_file.exists() {
            println!("cargo:rustc-cfg=has_circuit_{}", size);
            println!(
                "cargo:warning=Found compiled circuit: jwt_{}.cpp — enabling size '{}' support",
                size, size
            );
        }
    }

    // MDOC has no size variants — gate on a single `has_circuit_mdoc` cfg.
    println!("cargo::rustc-check-cfg=cfg(has_circuit_mdoc)");
    if circuits_dir.join("mdoc.cpp").exists() {
        println!("cargo:rustc-cfg=has_circuit_mdoc");
        println!("cargo:warning=Found compiled circuit: mdoc.cpp — enabling mdoc support");
    }

    // JSON-LD likewise: a single `has_circuit_jsonld` cfg.
    println!("cargo::rustc-check-cfg=cfg(has_circuit_jsonld)");
    if circuits_dir.join("jsonld.cpp").exists() {
        println!("cargo:rustc-cfg=has_circuit_jsonld");
        println!("cargo:warning=Found compiled circuit: jsonld.cpp — enabling jsonld support");
    }

    // Only run witnesscalc build when the native-witness feature is enabled.
    // WASM builds use JavaScript witness generation instead.
    #[cfg(feature = "native-witness")]
    {
        use std::path::Path;
        let circuits_path = circuits_dir.to_str().unwrap();

        // Check for pre-built witnesscalc cache from build_pod.sh
        if let Ok(witnesscalc_cache) = std::env::var("WITNESSCALC_PREBUILD_CACHE") {
            let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
            let target = std::env::var("TARGET").unwrap_or_default();

            // Only apply for iOS targets
            match target.as_str() {
                "aarch64-apple-ios-sim" | "aarch64-apple-ios" | "x86_64-apple-ios" => {
                    let cache_src = Path::new(&witnesscalc_cache);
                    let target_witnesscalc = Path::new(&out_dir).join("witnesscalc");

                    // Symlink entire witnesscalc directory if cache exists and target doesn't
                    if cache_src.exists() && !target_witnesscalc.exists() {
                        #[cfg(unix)]
                        {
                            println!(
                                "cargo:warning=Using cached witnesscalc from: {}",
                                cache_src.display()
                            );
                            std::os::unix::fs::symlink(&cache_src, &target_witnesscalc).ok();
                        }
                    }
                }
                _ => {}
            }
        }

        witnesscalc_adapter::build_and_link(circuits_path);

        // The adapter links the witnesscalc dylibs without an rpath, so the CLI
        // only starts under `cargo run`. Embed one so external callers (the
        // `jsonld verify-linked` verifier) can exec the binary directly.
        #[cfg(target_os = "macos")]
        if let Ok(out_dir) = std::env::var("OUT_DIR") {
            println!(
                "cargo:rustc-link-arg-bins=-Wl,-rpath,{out_dir}/witnesscalc/package/lib"
            );
        }
    }
}

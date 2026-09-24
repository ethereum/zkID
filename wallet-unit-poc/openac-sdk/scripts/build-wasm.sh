#!/bin/bash
set -euo pipefail

# Build the Spartan2 WASM module using wasm-pack
# This compiles the Rust prover to WebAssembly for use in the SDK

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_DIR="$(dirname "$SCRIPT_DIR")"
WASM_DIR="$SDK_DIR/wasm"

echo "=== Building OpenAC WASM module ==="
echo "WASM crate: $WASM_DIR"

# Check for wasm-pack
if ! command -v wasm-pack &> /dev/null; then
    echo "wasm-pack not found. Installing..."
    curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
fi

# Build with wasm-pack
echo "Building WASM module..."
cd "$WASM_DIR"
wasm-pack build \
    --target web \
    --out-dir pkg \
    --release \
    -- \
    --features "getrandom/js"

echo "=== WASM build complete ==="
echo "Output: $WASM_DIR/pkg/"

# wasm-pack writes pkg/.gitignore = '*', which also excludes pkg/ from the npm
# tarball despite files:['wasm/pkg']. Strip it so the bundled WASM actually ships.
rm -f "$WASM_DIR/pkg/.gitignore"

# Copy circuit artifacts if they exist
CIRCOM_BUILD="$SDK_DIR/../circom/build"
ASSETS_DIR="$SDK_DIR/assets"

if [ -d "$CIRCOM_BUILD" ]; then
    echo "Copying circuit artifacts to assets/..."

    # Copy R1CS + WASM witness calculator for each named circuit. The SDK
    # picks the per-size jwt_{1k|2k|4k|8k}.wasm at runtime based on the
    # requested VcSize.
    for name in jwt jwt_1k jwt_2k jwt_4k jwt_8k show mdoc; do
        src_dir="$CIRCOM_BUILD/$name/${name}_js"
        if [ -f "$src_dir/$name.r1cs" ]; then
            cp "$src_dir/$name.r1cs" "$ASSETS_DIR/$name.r1cs"
            echo "  Copied $name.r1cs"
        fi
        if [ -f "$src_dir/$name.wasm" ]; then
            cp "$src_dir/$name.wasm" "$ASSETS_DIR/$name.wasm"
            echo "  Copied $name.wasm (witness calculator)"
        fi
    done

    echo "Circuit artifacts copied to $ASSETS_DIR/"
else
    echo "Warning: Circom build directory not found at $CIRCOM_BUILD"
    echo "Run 'pnpm compile:all' from the circom directory first."
fi

# Bundle Show verifying keys (~3 MB each x 4 sizes = ~12 MB).
# Allows offline verification without R2 fetches.
SPARTAN_KEYS="$SDK_DIR/../ecdsa-spartan2/keys"
BUNDLED_KEYS_DIR="$ASSETS_DIR/keys"
if [ -d "$SPARTAN_KEYS" ]; then
    mkdir -p "$BUNDLED_KEYS_DIR"
    for size in 1k 2k 4k 8k; do
        src="$SPARTAN_KEYS/${size}_show_verifying.key"
        if [ -f "$src" ]; then
            cp "$src" "$BUNDLED_KEYS_DIR/${size}_show_verifying.key"
            echo "  Bundled ${size}_show_verifying.key"
        fi
    done
else
    echo "Warning: spartan2 keys dir not found at $SPARTAN_KEYS — show VKs not bundled."
fi

echo "=== Build complete ==="

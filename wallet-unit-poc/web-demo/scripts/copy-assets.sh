#!/bin/bash
# Copy required assets into the web-demo public/ and src/ directories.
# Run from the web-demo directory: bash scripts/copy-assets.sh
#
# Everything copied here is generated and untracked. Rerun this after
# rebuilding openac-sdk/wasm so the demo never serves a stale verifier.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WEB_DEMO_DIR="$(dirname "$SCRIPT_DIR")"
SDK_DIR="$WEB_DEMO_DIR/../openac-sdk"
KEYS_DIR="$WEB_DEMO_DIR/../ecdsa-spartan2/keys"
JWT_1K_WASM="$WEB_DEMO_DIR/../circom/build/jwt_1k/jwt_1k_js/jwt_1k.wasm"

need() {
  if [ ! -e "$1" ]; then
    echo "error: missing $1" >&2
    echo "       $2" >&2
    exit 1
  fi
}

echo "=== zkID Web Demo: Asset Setup ==="

PKG_HINT="Build it first: cd ../openac-sdk && npm run build:wasm (see openac-sdk/package.json)."
ASSET_HINT="Build the SDK circuit assets first (see openac-sdk/README.md)."

need "$SDK_DIR/wasm/pkg/openac_wasm.js" "$PKG_HINT"
need "$SDK_DIR/wasm/pkg/openac_wasm_bg.wasm" "$PKG_HINT"
need "$JWT_1K_WASM" "Compile the 1k JWT circuit first: cd ../circom && yarn compile:jwt:1k."
need "$SDK_DIR/assets/show.wasm" "$ASSET_HINT"
need "$SDK_DIR/assets/witness_calculator.js" "$ASSET_HINT"
need "$KEYS_DIR" "Generate the proving and verifying keys in ecdsa-spartan2 first."

# 1. WASM JS glue to src/wasm/ (Vite bundles it), binary to public/.
#    pipeline.ts checks abi_version() after loading.
echo "[1/4] Copying openac WASM module..."
mkdir -p "$WEB_DEMO_DIR/src/wasm" "$WEB_DEMO_DIR/public"
cp "$SDK_DIR/wasm/pkg/openac_wasm.js" "$WEB_DEMO_DIR/src/wasm/"
for f in openac_wasm.d.ts openac_wasm_bg.wasm.d.ts; do
  [ -e "$SDK_DIR/wasm/pkg/$f" ] && cp "$SDK_DIR/wasm/pkg/$f" "$WEB_DEMO_DIR/src/wasm/"
done
cp "$SDK_DIR/wasm/pkg/openac_wasm_bg.wasm" "$WEB_DEMO_DIR/public/"

# 2. Circuit WASM files. The demo builds 1k inputs and loads 1k keys, so jwt.wasm
#    comes from the circom 1k build. openac-sdk/assets/jwt.wasm is the default
#    circuit (maxMessageLength 1920) and fails with "Not enough values for input
#    signal message".
echo "[2/4] Copying circuit WASM files..."
cp "$JWT_1K_WASM" "$WEB_DEMO_DIR/public/jwt.wasm"
cp "$SDK_DIR/assets/show.wasm" "$WEB_DEMO_DIR/public/show.wasm"

# 3. witness_calculator.js to src/assets/ with the CJS export patched to ESM.
echo "[3/4] Copying witness calculator (CJS→ESM patch)..."
mkdir -p "$WEB_DEMO_DIR/src/assets"
cp "$SDK_DIR/assets/witness_calculator.js" "$WEB_DEMO_DIR/src/assets/"
# Vite only does CJS→ESM for node_modules, not src/ files.
sed -i.bak 's/^module\.exports = async function builder/export default async function builder/' \
  "$WEB_DEMO_DIR/src/assets/witness_calculator.js"
rm -f "$WEB_DEMO_DIR/src/assets/witness_calculator.js.bak"

# 4. Keys. A relative link, so it survives moving the checkout.
echo "[4/4] Linking keys directory..."
rm -rf "$WEB_DEMO_DIR/public/keys"
ln -s "../../ecdsa-spartan2/keys" "$WEB_DEMO_DIR/public/keys"

echo ""
echo "=== Done! ==="
echo "Run with: npm run dev"

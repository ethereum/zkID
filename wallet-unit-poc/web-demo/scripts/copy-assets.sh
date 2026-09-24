#!/bin/bash
# Copy required assets into the web-demo public/ and src/ directories.
# Run from the web-demo directory: bash scripts/copy-assets.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WEB_DEMO_DIR="$(dirname "$SCRIPT_DIR")"
SDK_DIR="$WEB_DEMO_DIR/../openac-sdk"
KEYS_DIR="$WEB_DEMO_DIR/../ecdsa-spartan2/keys"

echo "=== zkID Web Demo: Asset Setup ==="

# 1. Copy WASM JS glue to src/wasm/ (Vite bundles it)
#    Copy WASM binary to public/ (served as static file)
echo "[1/5] Copying openac WASM module..."
mkdir -p "$WEB_DEMO_DIR/src/wasm"
cp "$SDK_DIR/wasm/pkg/openac_wasm.js" "$WEB_DEMO_DIR/src/wasm/"
cp "$SDK_DIR/wasm/pkg/openac_wasm.d.ts" "$WEB_DEMO_DIR/src/wasm/"
cp "$SDK_DIR/wasm/pkg/openac_wasm_bg.wasm" "$WEB_DEMO_DIR/public/"

# 2. Copy circom circuit WASM files to public/ (must match key size!)
CIRCOM_DIR="$WEB_DEMO_DIR/../circom/build"
echo "[2/5] Copying circuit WASM files (1k)..."
cp "$CIRCOM_DIR/jwt_1k/jwt_1k_js/jwt_1k.wasm" "$WEB_DEMO_DIR/public/jwt.wasm"
cp "$CIRCOM_DIR/show/show_js/show.wasm" "$WEB_DEMO_DIR/public/show.wasm"

# 3. Copy witness_calculator.js to src/assets/ and patch CJS→ESM export
echo "[3/5] Copying witness calculator (CJS→ESM patch)..."
mkdir -p "$WEB_DEMO_DIR/src/assets"
cp "$SDK_DIR/assets/witness_calculator.js" "$WEB_DEMO_DIR/src/assets/"
# Vite only does CJS→ESM for node_modules, not src/ files.
# Patch the CJS module.exports to an ESM default export.
sed -i '' 's/^module\.exports = async function builder/export default async function builder/' \
  "$WEB_DEMO_DIR/src/assets/witness_calculator.js"

# 4. Symlink keys directory
echo "[4/5] Symlinking keys directory..."
if [ -L "$WEB_DEMO_DIR/public/keys" ]; then
  rm "$WEB_DEMO_DIR/public/keys"
fi
if [ -d "$WEB_DEMO_DIR/public/keys" ]; then
  rm -rf "$WEB_DEMO_DIR/public/keys"
fi
ln -s "$KEYS_DIR" "$WEB_DEMO_DIR/public/keys"

echo ""
echo "=== Done! ==="
echo "Verify with: ls -la public/ && ls src/wasm/ && ls src/assets/"
echo "Run with:    pnpm dev"

#!/usr/bin/env bash
# Generates the circuit assets and flow fixtures the mobile app bundles.
# Nothing it writes is committed; rerunning produces byte-identical output.
# Output is staged in a temp directory and moved into place only after every
# step succeeds. The final moves are not atomic.
set -euo pipefail

MOBILE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WALLET_DIR="$(cd "$MOBILE_DIR/.." && pwd)"
CIRCOM_DIR="$WALLET_DIR/circom"
SDK_DIR="$WALLET_DIR/openac-sdk"
ASSETS_DIR="$MOBILE_DIR/flutter/assets"
BUILD_DIR="$CIRCOM_DIR/build"
JWT_R1CS="$BUILD_DIR/jwt_2k/jwt_2k.r1cs"
SHOW_R1CS="$BUILD_DIR/show/show.r1cs"
STAMP="$BUILD_DIR/.mobile-assets-stamp"
# Everything that determines the compiled circuits. @zk-email/circuits comes
# from node_modules, so package.json and yarn.lock stand in for it.
SOURCE_PATHS=(
  ":/wallet-unit-poc/circom/circuits"
  ":/wallet-unit-poc/circom/circuits.json"
  ":/wallet-unit-poc/circom/circomkit.json"
  ":/wallet-unit-poc/circom/package.json"
  ":/wallet-unit-poc/circom/yarn.lock"
)

sha256_of() { shasum -a 256 "$1" | cut -d' ' -f1; }

source_commit="$(git -C "$WALLET_DIR" log -1 --format=%H -- "${SOURCE_PATHS[@]}")"
# Uncommitted edits have no stable identity: always rebuild, and say so.
if [ -n "$(git -C "$WALLET_DIR" status --porcelain -- "${SOURCE_PATHS[@]}")" ]; then
  source_commit="$source_commit-dirty"
fi

# Reuse the build only if the stamp matches this source identity. The stamp is
# removed before compiling and written after both compiles succeed, so an
# interrupted compile leaves no stamp.
if [ ! -f "$BUILD_DIR/cpp/jwt_2k.cpp" ] || [ ! -f "$BUILD_DIR/cpp/show.cpp" ] \
  || [ ! -f "$JWT_R1CS" ] || [ ! -f "$SHOW_R1CS" ] \
  || [[ "$source_commit" == *-dirty ]] \
  || [ "$(cat "$STAMP" 2>/dev/null || true)" != "$source_commit" ]; then
  rm -f "$STAMP"
  (cd "$CIRCOM_DIR" && yarn install --frozen-lockfile && yarn compile:jwt:2k && yarn compile:show)
  echo "$source_commit" > "$STAMP"
else
  echo "circuit build up to date ($source_commit)"
fi

if [ ! -x "$SDK_DIR/node_modules/.bin/tsx" ]; then
  (cd "$SDK_DIR" && npm ci)
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/circom" "$STAGE/flow"

gzip -9 -n -c "$JWT_R1CS" > "$STAGE/circom/jwt.r1cs.gz"
gzip -9 -n -c "$SHOW_R1CS" > "$STAGE/circom/show.r1cs.gz"

(cd "$SDK_DIR" && npm run --silent gen:mobile-fixtures -- --circom-build "$BUILD_DIR" --out "$STAGE")

cat > "$STAGE/circom/manifest.json" <<JSON
{
  "jwtR1csSha256": "$(sha256_of "$JWT_R1CS")",
  "showR1csSha256": "$(sha256_of "$SHOW_R1CS")",
  "sourceCommit": "$source_commit"
}
JSON

mkdir -p "$ASSETS_DIR/circom" "$ASSETS_DIR/flow"
mv -f "$STAGE"/circom/* "$ASSETS_DIR/circom/"
mv -f "$STAGE"/flow/* "$ASSETS_DIR/flow/"

echo "assets ready in $ASSETS_DIR"

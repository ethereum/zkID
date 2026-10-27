#!/bin/bash
set -e

# Verifies proofs pulled from a phone against the pinned verifying keys.
#
# Usage: verify_device_proofs.sh <dir with *.proof> [vk_dir]
#   adb pull /sdcard/Android/data/com.openac.app/files/out ./out
#   verify_device_proofs.sh ./out
# vk_dir defaults to ecdsa-spartan2/keys (2k_prepare_verifying.key, 2k_show_verifying.key).
# Prints PASS or FAIL per file; exits non-zero on any failure.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MOBILE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROOFS_DIR="${1:?usage: $0 <proofs_dir> [vk_dir]}"
PROOFS_DIR="$(cd "$PROOFS_DIR" && pwd)"
VK_DIR="${2:-$MOBILE_DIR/../ecdsa-spartan2/keys}"
VK_DIR="$(cd "$VK_DIR" && pwd)"

cd "$MOBILE_DIR"
# Compiler warnings from the workspace are noise here; show the full output only if the build fails.
cargo build --release --quiet --bin verify_proofs 2>/dev/null || cargo build --release --bin verify_proofs
exec "${CARGO_TARGET_DIR:-$MOBILE_DIR/target}/release/verify_proofs" "$PROOFS_DIR" "$VK_DIR"

#!/bin/bash
set -e

# Verifies proofs pulled from a phone against the pinned verifying keys. The
# present pair is also checked for linkage (shared comm_W_shared).
#
# Usage: verify_device_proofs.sh <dir with *.proof> [vk_dir]
#   adb pull /sdcard/zkbench/com.openac.app/out ./out
#   verify_device_proofs.sh ./out
# vk_dir defaults to ecdsa-spartan2/keys (2k_prepare_verifying.key, 2k_show_verifying.key).
# The last output lines are PASS or FAIL per check; exits non-zero on any failure.
# Cargo's own output goes to a log, which is printed only if the build or run fails
# without producing a verdict.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MOBILE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROOFS_DIR="${1:?usage: $0 <proofs_dir> [vk_dir]}"
PROOFS_DIR="$(cd "$PROOFS_DIR" && pwd)"
VK_DIR="${2:-$MOBILE_DIR/../ecdsa-spartan2/keys}"
VK_DIR="$(cd "$VK_DIR" && pwd)"

LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT
cd "$MOBILE_DIR"

if ! cargo build --release --bin verify_proofs >"$LOG" 2>&1; then
    cat "$LOG"
    exit 1
fi

# cargo run sets the library path the witnesscalc dylib needs.
set +e
VERDICT="$(cargo run --release --quiet --bin verify_proofs -- "$PROOFS_DIR" "$VK_DIR" 2>"$LOG")"
RC=$?
set -e
if [ -z "$VERDICT" ]; then
    tail -n 20 "$LOG"
else
    echo "$VERDICT"
fi
exit $RC

#!/bin/bash
set -e

# Builds the arm64 profile APKs for the host-driven benchmark (bench_workload.json):
# the app, with the integration test as its entry point, and the androidTest APK.
# Same sources as build_ftl_apks.sh, but this build only runs the contract harness;
# the Firebase Test Lab configs are left out (BENCH_CONTRACT=1).
#
# The APKs are copied out of the Flutter build dirs, which build_ftl_apks.sh also
# writes, so a later Firebase build can never replace what the runner installs.
#
# Usage: build_bench_apks.sh
# Outputs (the paths bench_workload.json lists):
#   ../build/bench-apks/app-profile.apk
#   ../build/bench-apks/app-profile-androidTest.apk

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$PROJECT_ROOT/build/bench-apks"

export JAVA_HOME="${JAVA_HOME:-/Applications/Android Studio.app/Contents/jbr/Contents/Home}"
export NDK_VERSION="${NDK_VERSION:-27.0.12077973}"
export BENCH_CONTRACT=1

# The Flutter tooling rewrites these two tracked files during a build (analyzer
# excludes, Kotlin migrator flags). Put them back on exit, like the asset restore
# in build_ftl_apks.sh, so a build leaves the tree clean.
TOUCHED=("$PROJECT_ROOT/flutter/analysis_options.yaml" "$PROJECT_ROOT/flutter/android/gradle.properties")
BACKUP="$(mktemp -d)"
for f in "${TOUCHED[@]}"; do cp "$f" "$BACKUP/$(basename "$f")"; done
trap 'for f in "${TOUCHED[@]}"; do cp "$BACKUP/$(basename "$f")" "$f"; done; rm -rf "$BACKUP"' EXIT

"$SCRIPT_DIR/build_ftl_apks.sh"

FLUTTER_OUT="$PROJECT_ROOT/flutter/build/app/outputs"
mkdir -p "$OUT_DIR"
cp "$FLUTTER_OUT/flutter-apk/app-profile.apk" "$OUT_DIR/app-profile.apk"
cp "$FLUTTER_OUT/apk/androidTest/profile/app-profile-androidTest.apk" "$OUT_DIR/app-profile-androidTest.apk"

echo ""
echo "Bench APKs in $OUT_DIR"

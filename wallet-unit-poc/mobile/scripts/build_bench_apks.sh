#!/bin/bash
set -e

# Builds the arm64 profile APKs for the host-driven benchmark (bench_workload.json):
# the app, with the integration test as its entry point, and the androidTest APK.
# They are the same APKs build_ftl_apks.sh makes; with a bench_config.json on the
# device the test runs the contract harness instead of the Firebase Test Lab configs.
#
# Usage: build_bench_apks.sh
# Outputs (the paths bench_workload.json lists):
#   ../flutter/build/app/outputs/flutter-apk/app-profile.apk
#   ../flutter/build/app/outputs/apk/androidTest/profile/app-profile-androidTest.apk

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

export JAVA_HOME="${JAVA_HOME:-/Applications/Android Studio.app/Contents/jbr/Contents/Home}"
export NDK_VERSION="${NDK_VERSION:-27.0.12077973}"

# One iteration, no cooldown: the Firebase configs are not used by this harness.
exec "$SCRIPT_DIR/build_ftl_apks.sh" --smoke

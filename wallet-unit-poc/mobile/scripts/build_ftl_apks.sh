#!/bin/bash
set -e

# Builds the arm64 profile APKs that Firebase Test Lab runs: the app with the
# benchmark integration test as its entry point, and the androidTest APK.
#
# Usage: build_ftl_apks.sh [--smoke]
#   --smoke   one iteration per config, no warm-up, no cooldown (BENCH_SMOKE=1 works too)
# Iteration counts otherwise come from BENCH_WARMUP, BENCH_ITERS_A, BENCH_ITERS_B, BENCH_ITERS_P
# and BENCH_COOLDOWN_S, defaulting to the test's own defaults.
#
# GMP and witnesscalc are cached per build dir. After changing NDKs, delete
# flutter/build (or the ecdsa-spartan2-* dirs under it) before rebuilding.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FLUTTER_DIR="$PROJECT_ROOT/flutter"

TARGET="integration_test/android_bench_test.dart"
PLATFORM="android-arm64"

SMOKE=0
[ "$BENCH_SMOKE" = "1" ] && SMOKE=1
for arg in "$@"; do
    case "$arg" in
        --smoke) SMOKE=1 ;;
        *)
            echo "Unknown argument: $arg" >&2
            exit 1
            ;;
    esac
done

if [ "$SMOKE" = "1" ]; then
    BENCH_WARMUP=0
    BENCH_ITERS_A=1
    BENCH_ITERS_B=1
    BENCH_ITERS_P=1
    BENCH_COOLDOWN_S=0
fi

# witnesscalc's Android GMP build reads ANDROID_NDK. Default to the NDK cargokit
# compiles the Rust crate with (the one AGP resolves for the bindings module), so
# GMP and the rest of the library link against the same libc++.
NDK_VERSION="${NDK_VERSION:-27.0.12077973}"
SDK_DIR="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
export ANDROID_NDK="${ANDROID_NDK:-$SDK_DIR/ndk/$NDK_VERSION}"
if [ "$(basename "$ANDROID_NDK")" != "$NDK_VERSION" ]; then
    echo "Warning: cargokit compiles with NDK $NDK_VERSION but ANDROID_NDK is $ANDROID_NDK;" >&2
    echo "mixed NDKs risk libc++ mismatches." >&2
fi
if [ ! -d "$ANDROID_NDK" ]; then
    echo "NDK not found at $ANDROID_NDK (sdkmanager \"ndk;$NDK_VERSION\")" >&2
    exit 1
fi

# ./gradlew needs the JDK Flutter uses (often Android Studio's bundled JBR),
# not the macOS /usr/bin/java stub.
if [ -z "$JAVA_HOME" ]; then
    JAVA_BIN="$(flutter doctor -v 2>/dev/null | sed -n 's/.*Java binary at: //p' | head -1)"
    if [ -n "$JAVA_BIN" ]; then
        export JAVA_HOME="$(dirname "$(dirname "$JAVA_BIN")")"
    fi
fi

DEFINES=()
for var in BENCH_WARMUP BENCH_ITERS_A BENCH_ITERS_B BENCH_ITERS_P BENCH_COOLDOWN_S; do
    if [ -n "${!var}" ]; then
        DEFINES+=("--dart-define=$var=${!var}")
    fi
done

# The committed assets can lag the circuit, and the APK must carry an r1cs and
# inputs that match the witnesscalc C++ compiled into the same build. Stage them
# from the local circom outputs and put the tracked files back on exit.
CIRCOM_DIR="$(cd "$PROJECT_ROOT/../circom" && pwd)"
ASSETS_DIR="$FLUTTER_DIR/assets/circom"
JWT_R1CS="$CIRCOM_DIR/build/jwt_2k/jwt_2k_js/jwt_2k.r1cs"
SHOW_R1CS="$CIRCOM_DIR/build/show/show_js/show.r1cs"
JWT_INPUT="$CIRCOM_DIR/inputs/jwt/2k/default.json"
SHOW_INPUT="$CIRCOM_DIR/inputs/show/2k/default.json"
for f in "$JWT_R1CS" "$SHOW_R1CS" "$JWT_INPUT" "$SHOW_INPUT"; do
    if [ ! -f "$f" ]; then
        echo "Missing $f" >&2
        echo "Compile the circuits first: (cd $CIRCOM_DIR && yarn compile:jwt:2k && yarn compile:show)" >&2
        exit 1
    fi
done

# A killed earlier run can leave staged files behind; never back those up.
if [ -n "$(git -C "$FLUTTER_DIR" status --porcelain -- "$ASSETS_DIR")" ]; then
    echo "$ASSETS_DIR has uncommitted changes; restore with: git checkout -- $ASSETS_DIR" >&2
    exit 1
fi

ASSETS_BACKUP="$(mktemp -d)"
cp "$ASSETS_DIR"/* "$ASSETS_BACKUP"/
trap 'cp "$ASSETS_BACKUP"/* "$ASSETS_DIR"/; rm -rf "$ASSETS_BACKUP"' EXIT

gzip -9 -c "$JWT_R1CS" > "$ASSETS_DIR/jwt.r1cs.gz"
gzip -9 -c "$SHOW_R1CS" > "$ASSETS_DIR/show.r1cs.gz"
cp "$JWT_INPUT" "$ASSETS_DIR/jwt_input.json"
cp "$SHOW_INPUT" "$ASSETS_DIR/show_input.json"

cd "$FLUTTER_DIR"

echo "=================================================="
echo "Building app APK (profile, $PLATFORM, ${DEFINES[*]:-default iteration counts})"
echo "=================================================="
flutter build apk --profile --target-platform "$PLATFORM" \
    --android-skip-build-dependency-validation \
    --target "$TARGET" "${DEFINES[@]}"

echo "=================================================="
echo "Building androidTest APK"
echo "=================================================="
# Gradle takes dart-defines as comma-separated base64 values.
GRADLE_DEFINES=""
for d in "${DEFINES[@]}"; do
    GRADLE_DEFINES+="$(printf '%s' "${d#--dart-define=}" | base64),"
done
GRADLE_DEFINES="${GRADLE_DEFINES%,}"

cd "$FLUTTER_DIR/android"
./gradlew app:assembleAndroidTest \
    -Ptarget="$FLUTTER_DIR/$TARGET" \
    -Ptarget-platform="$PLATFORM" \
    -PskipDependencyChecks=true \
    ${GRADLE_DEFINES:+-Pdart-defines="$GRADLE_DEFINES"}

APP_APK="$FLUTTER_DIR/build/app/outputs/flutter-apk/app-profile.apk"
TEST_APK="$FLUTTER_DIR/build/app/outputs/apk/androidTest/profile/app-profile-androidTest.apk"

echo ""
echo "App APK:  $APP_APK"
echo "Test APK: $TEST_APK"

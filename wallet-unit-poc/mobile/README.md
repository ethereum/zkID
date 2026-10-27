# OpenAC Mobile Wallet-Unit-PoC

Mobile App for [OpenAC Wallet-Unit-PoC](/wallet-unit-poc/ecdsa-spartan2/), support both Android and iOS through Flutter.

## Prerequisites

Before getting started, ensure you have the Flutter SDK installed:

1. Install Flutter SDK (3.0.0 or higher) from the [official Flutter installation guide](https://docs.flutter.dev/get-started/install)

2. Verify your installation:

    ```sh
    flutter doctor
    ```

> For more details, see [Mopro Prerequisites](https://zkmopro.org/docs/prerequisites)

## Getting Started

### 1. Install the Mopro CLI Tool

```sh
cargo install mopro-cli
```

### 2. iOS Configuration (iOS targets only)

Before building for iOS, configure Xcode and install Rust iOS targets.

1. **Install Xcode** from the App Store or [Apple Developer](https://developer.apple.com/xcode/)

2. **Configure Command Line Tools**: Open Xcode > Settings > Locations and verify the Command Line Tools path is set

3. **Install Rust iOS Targets**:

    ```bash
    # For iOS device (arm64)
    rustup target add aarch64-apple-ios

    # For iOS simulator (arm64, Apple Silicon)
    rustup target add aarch64-apple-ios-sim
    ```

> **Note**: x86_64 iOS simulator is not supported. See [Notes](#note) section for details.

> For more details, see [Mopro Prerequisites - iOS](https://zkmopro.org/docs/prerequisites#ios)

### 3. Android Configuration (Android targets only)

Before building for Android, install Android Studio and configure the NDK environment. The Rust FFI bindings require NDK for cross-compilation.

1. **Install Android Studio** from [developer.android.com/studio](https://developer.android.com/studio)

2. **Install JDK**: Download from [Oracle](https://www.oracle.com/java/technologies/downloads/) or use your package manager

3. **Install NDK** via Android Studio: `SDK Manager > SDK Tools > NDK (Side by Side)`

4. **Install Rust Android Targets**:

    ```bash
    rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
    ```

5. **Set environment variables** in your shell config (`~/.zshrc` or `~/.bashrc`):

    ```bash
    # Android SDK
    export ANDROID_HOME="$HOME/Library/Android/sdk"

    # Find your NDK version
    ls $ANDROID_HOME/ndk  # e.g., 26.1.10909125

    # Set NDK path (replace version with yours)
    export NDK_PATH="$ANDROID_HOME/ndk/26.1.10909125"
    ```

6. Reload your shell or run `source ~/.zshrc`

> For more details, see [Mopro Prerequisites - Android Configuration](https://zkmopro.org/docs/prerequisites#android-configuration)

### 4. Flutter App

#### 4(a). Generate Flutter Bindings

These's already default [Flutter bindings](/wallet-unit-poc/mobile/mopro_flutter_bindings/), so no need to manually generate a new one.

However, if you want to play around with your own tweak version, see [Mopro Flutter Setup](https://zkmopro.org/docs/setup/flutter-setup) for generating a custom bindings.

#### 4(b). Connect Devices or Run Emulators

```sh
# Check Available Devices
flutter devices

# Start iOS Simulator or Android Emulator
flutter emulator --launch <EMULATOR_TYPE>
```

#### 4(c). Run Flutter with Release Mode

```sh
cd flutter
flutter run --release
```

## Timing Measurements (Mobile)

All timing measurements are in milliseconds (ms).

**Test Device:** 
- iOS: iPhone 17, A19 chip, 8GB RAM
- Android: Pixel 10 Pro, Tensor G5, 16GB of RAM

### Prepare Circuit Timing

- Payload Size: 1920 Bytes
- Peak Memory Usage for Proving: 2.27 GiB

|    Device    | Setup (ms) | Prove (ms) | Reblind (ms) | Verify (ms) |
|:------------:|:----------:|:----------:|:------------:|:-----------:|
|  iPhone 17   |    3254    |    2102    |     884      |     137     |
| Pixel 10 Pro |    9282    |    5161    |     1732     |     318     |


### Show Circuit Timing

The Show circuit has constant performance regardless of JWT payload size.
- Peak Memory Usage for Proving: 1.96 GiB

|    Device    | Setup (ms) | Prove (ms) | Reblind (ms) | Verify (ms) |
|:------------:|:----------:|:----------:|:------------:|:-----------:|
|  iPhone 17   |     43     |     85     |      30      |     13      |
| Pixel 10 Pro |     99     |    308     |     130      |     65      |

| iPhone 17 | Pixel 10 Pro |
|-----------|--------------|
| <img src="/wallet-unit-poc/mobile/assets/openac-iphone-17.jpg" width="300"> | <img src="/wallet-unit-poc/mobile/assets/openac-pixel-10-pro.jpg" width="300"> |

## Host-driven Android benchmark

`scripts/bench_workload.json` drives the benchmark from a host runner: Prepare, Show and a full
presentation (`present`: Show prove plus Prepare and Show reblind), each in a fresh process, with
proving keys pushed from the host instead of generated on the device.

1. `scripts/build_bench_apks.sh` builds the app and androidTest APKs (arm64, profile).
2. Install both with `adb install -r -t`.
3. After install, `adb shell appops set com.openac.app MANAGE_EXTERNAL_STORAGE allow` (the profile
   manifest declares it; on API 29 and lower `pm grant` the storage permissions instead). Then
   `adb shell mkdir -p /sdcard/zkbench/com.openac.app` and push the files listed under `push`
   into it. The shell can write there on every API level, unlike the app's external files dir.
4. Write one run's `config` to `bench_config.json` in the same directory, then
   `adb shell am instrument -w -r com.openac.app.test/androidx.test.runner.AndroidJUnitRunner`.
5. Parse logcat with `scripts/parse_ftl_bench.py` (`OPENAC_ITER` lines).
6. `adb pull /sdcard/zkbench/com.openac.app/out`, then `scripts/verify_device_proofs.sh <dir>` verifies the proofs of the last iteration against the pinned verifying keys (host only; the Prepare vk is 432 MB). Files: `prepare`, `show`, `present_prepare`, `present_show`, each as `.proof` and `.instance`.

Without a `bench_config.json` the same APKs run the Firebase Test Lab configs (setup on device).

The harness copies the needed files to internal storage and drops them from the page cache before
iteration 0, so the cold key load reads from storage. The device needs no r1cs: witnesses come from
the compiled-in witnesscalc. Prepare's `prove_ms` includes `witness_ms`; Show's witness cannot be
timed apart. `low_memory_mode` is not implemented.

`2k_prepare_instance.bin` and `2k_prepare_witness.bin` must come from a Prepare proof that has not
been reblinded; the desktop `benchmark` flow leaves reblinded copies in `keys/`, which a second
reblind rejects.

## Note

### Excluded x86_64 iOS simulator in `mopro_flutter_bindings/ios/mopro_flutter_bindings.podspec`

```podspec
# Flutter.framework does not contain a i386 slice.
# exclude x86_64 since w2c2 is not supported on x86_64-ios simulator build
'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386 x86_64',
```

# Cross-Platform Mobile ZKPs

> [!IMPORTANT]
> This code is a reference implementation. It has not been checked for production quality.
>
> Only an internal audit has been completed. The code has not had an external audit.

Flutter is a popular cross-platform mobile app development framework. Mopro Flutter shows an example of integrating ZK-proving into a Flutter app, allowing for streamlined creation of ZK-enabled mobile apps.

> [!IMPORTANT]
> Please refer to the latest [mopro documentation](https://zkmopro.org/docs/next/setup/flutter-setup) for the most up-to-date information.

## Running The Example App

### Prerequisites

1. **Install Flutter**

    If Flutter is not already installed, you can follow the [official Flutter installation guide](https://docs.flutter.dev/get-started/install) for your operating system.

2. **Check Flutter Environment**

    After installing Flutter, verify that your development environment is properly set up by running the following command in your terminal:

    ```bash
    flutter doctor
    ```

    This command will identify any missing dependencies or required configurations.

3. **Install Flutter Dependencies**

    Navigate to the root directory of the project in your terminal and run:

    ```bash
    flutter pub get
    ```

    This will install the necessary dependencies for the project.

### Running the App via VS Code

1. Open the project in VS Code.
2. Open the "Run and Debug" panel.
3. Start an emulator (iOS/Android) or connect your physical device.
4. Select "example" in the run menu and press "Run".

### Running the App via Console

If you prefer using the terminal to run the app, use the following steps:

1. For Android:

    Ensure you have an Android emulator running or a device connected. Then run:

    ```bash
    flutter run
    ```

2. For iOS:

    Make sure you have an iOS simulator running or a device connected. Then run:

    ```bash
    flutter run
    ```

## Integrating Your ZKP

The example app comes with a simple prover generated from a Circom circuit. To integrate your own prover, follow the steps below.

> [!WARNING]  
> In the `frb` branch, the example app uses [`flutter_rust_bridge`](https://github.com/fzyzcjy/flutter_rust_bridge) to generate bindings. If you need to work with `mopro-ffi` or `mopro-cli` versions earlier than `0.3.0`, please switch to the `main` branch or the `v0.2.0` tag.

### Setup

-   Install the latest mopro CLI on GitHub

```sh
git clone https://github.com/zkmopro/mopro
cd mopro/cli
cargo install --path .
```

<!-- TODO: publish this version of mopro-cli -->

-   Follow the [Getting Started](https://zkmopro.org/docs/getting-started/) guide to run
    ```sh
    mopro init
    ```
    (select your preferred adapter) and then
    ```sh
    mopro build
    ```
    to generate the `mopro_flutter_bindings`.

### Copying The Generated Libraries

After running `mopro build`, copy the generated `mopro_flutter_bindings`. If you add new functions with `flutter_rust_bridge` and want to use them in Flutter, run `mopro build` again to regenerate and update the bindings.

### zKey

1. Place your `.zkey` file in your app's assets folder. For example, to run the included example app, you need to replace the `.zkey` at [`assets/multiplier2_final.zkey`](assets/multiplier2_final.zkey) with your file. If you change the `.zkey` file name, don't forget to update the asset definition in your app's [`pubspec.yaml`](pubspec.yaml):

    ```yaml
    assets:
        - assets/your_new_zkey_file.zkey
    ```

2. Load the new `.zkey` file properly in your Dart code. For example, update the file path in [`lib/main.dart`](lib/main.dart):

    ```dart
    var inputs = "{\"a\":[\"3\"],\"b\":[\"5\"]}";
    proofResult = await generateCircomProof(
                        zkeyPath: zkeyPath,
                        circuitInputs: inputs,
                        proofLib: ProofLib.arkworks);
    ```

Don't forget to modify the input values for your specific case!

## Developing The Plugin

### Android

Open the `./android` directory in Android Studio. You will be able to browse to the plugin code in `Android` and `Project` view.

## E2E Tests

### End-to-End (E2E) / Integration Tests

1. Start an emulator or simulator

    - iOS: Open the iOS simulator via Xcode or `open -a Simulator`.

    - Android: Launch an emulator using Android Studio or `emulator -avd <your_avd_name>`.
        > [!NOTE]  
        > If you encounter the error `command not found: emulator`, ensure the emulator binary is present in one of the following locations:
        >
        > - `~/Library/Android/sdk/emulator/emulator`
        > - `~/Android/Sdk/emulator/emulator`
        >
        > To resolve this issue, update your shell configuration file (likely `~/.zshrc`) by adding the following lines:
        >
        > ```sh
        > export ANDROID_SDK_ROOT=~/Library/Android/sdk
        > export PATH=$PATH:$ANDROID_SDK_ROOT/emulator
        > ```
        >
        > After making these changes, verify that the issue is resolved by running:
        >
        > ```sh
        > emulator -list-avds
        > ```

2. Run the integration test

```sh
flutter test integration_test/plugin_integration_test.dart
```

> Make sure you're using a real or virtual device (not just a Dart VM), as integration tests require it.

### Widget & Unit Tests

To run unit and widget tests (headless, using Dart VM):

```sh
flutter test
```

These are ideal for testing individual widgets, business logic, and pure Dart code.

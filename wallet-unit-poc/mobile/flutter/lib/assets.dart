import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart'
    show FlutterError, debugPrint, listEquals;
import 'package:flutter/services.dart' show ByteData, rootBundle;
import 'package:path_provider/path_provider.dart';

import 'flow/flow_models.dart';

/// A generated asset is not in the app bundle. They are not in git; run
/// `scripts/prepare-assets.sh` to create them.
class MissingAssetsException implements Exception {
  final String asset;

  const MissingAssetsException(this.asset);

  @override
  String toString() =>
      'Missing asset $asset. Run scripts/prepare-assets.sh, then rebuild the app.';
}

typedef AssetLoader = Future<ByteData> Function(String key);

Future<ByteData> _loadAsset(String key) async {
  try {
    return await rootBundle.load(key);
  } on FlutterError {
    throw MissingAssetsException(key);
  }
}

/// Directory holding the circuit files, passed to Rust as `documents_path`.
Future<String> getDocumentsPath() async {
  final dir = await getApplicationDocumentsDirectory();
  return '${dir.path}/circom';
}

/// Copies the circuit assets into place and returns the documents path.
Future<String> prepareAssets() async {
  final path = await getDocumentsPath();
  await extractAssets(Directory(path));
  return path;
}

Future<FlowBundle> loadFlowBundle() async {
  final data = await _loadAsset('assets/flow/bundle.json');
  return FlowBundle.fromJson(jsonDecode(utf8.decode(data.buffer.asUint8List()))
      as Map<String, dynamic>);
}

/// Copy circuit files from Flutter assets into [circomDir], mirroring the
/// layout used by Rust's PathConfig::mobile:
///
///   {docs}/build/jwt/jwt_js/jwt.r1cs   ← decompressed from jwt.r1cs.gz
///   {docs}/build/show/show_js/show.r1cs ← decompressed from show.r1cs.gz
///   {docs}/jwt_input.json               ← flow prepare + benchmark
///   {docs}/show_input.json              ← benchmark
///   {docs}/manifest.json                ← copy of the bundled manifest
///
/// The manifest is written last. A different or missing one means the files
/// on disk came from another build, so the r1cs and keys are discarded.
Future<void> extractAssets(Directory circomDir,
    {AssetLoader load = _loadAsset}) async {
  final bundled =
      (await load('assets/circom/manifest.json')).buffer.asUint8List();
  final manifest = File('${circomDir.path}/manifest.json');
  if (!await manifest.exists() ||
      !listEquals(await manifest.readAsBytes(), bundled)) {
    for (final name in ['build', 'keys']) {
      final dir = Directory('${circomDir.path}/$name');
      if (await dir.exists()) await dir.delete(recursive: true);
    }
  }

  final jwtBuildDir = Directory('${circomDir.path}/build/jwt/jwt_js');
  final showBuildDir = Directory('${circomDir.path}/build/show/show_js');
  await jwtBuildDir.create(recursive: true);
  await showBuildDir.create(recursive: true);

  // Skip if already extracted (each is ~350MB).
  final compressedAssets = {
    'assets/circom/jwt.r1cs.gz': '${jwtBuildDir.path}/jwt.r1cs',
    'assets/circom/show.r1cs.gz': '${showBuildDir.path}/show.r1cs',
  };
  for (final entry in compressedAssets.entries) {
    final target = File(entry.value);
    if (!await target.exists()) {
      debugPrint('Decompressing ${entry.key}');
      final data = await load(entry.key);
      final decompressed = gzip.decode(data.buffer.asUint8List());
      await target.writeAsBytes(decompressed);
      debugPrint(
          '  → ${(decompressed.length / 1024 / 1024).toStringAsFixed(2)} MB');
    }
  }

  await _writeInputAssets(circomDir, load);
  await manifest.writeAsBytes(bundled);
}

/// Always overwrite input JSON files so stale cached versions from a previous
/// app install never cause witness synthesis mismatches.
Future<void> _writeInputAssets(Directory circomDir, AssetLoader load) async {
  const inputAssets = ['jwt_input.json', 'show_input.json'];
  for (final name in inputAssets) {
    final data = await load('assets/circom/$name');
    final dest = '${circomDir.path}/$name';
    await File(dest).writeAsBytes(data.buffer.asUint8List());
    debugPrint('Wrote assets/circom/$name → $dest');
  }
}

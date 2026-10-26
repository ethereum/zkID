import 'dart:io';
import 'package:flutter/foundation.dart' show debugPrint;
import 'package:flutter/services.dart' show rootBundle;
import 'package:path_provider/path_provider.dart';

/// Directory holding the circuit files, passed to Rust as `documents_path`.
Future<String> getDocumentsPath() async {
  final dir = await getApplicationDocumentsDirectory();
  return '${dir.path}/circom';
}

/// Copies the circuit assets into place and returns the documents path.
Future<String> prepareAssets() async {
  await _copyAssetsToDocuments();
  return getDocumentsPath();
}

/// Copy circuit files from Flutter assets into the app's documents directory,
/// mirroring the layout used by Rust's PathConfig::mobile:
///
///   {docs}/build/jwt/jwt_js/jwt.r1cs   ← decompressed from jwt.r1cs.gz
///   {docs}/build/show/show_js/show.r1cs ← decompressed from show.r1cs.gz
///   {docs}/jwt_input.json               ← prove_jwt + run_complete_benchmark
///   {docs}/show_input.json              ← prove_show + run_complete_benchmark
Future<void> _copyAssetsToDocuments() async {
  try {
    final documentsDir = await getApplicationDocumentsDirectory();
    final circomDir = Directory('${documentsDir.path}/circom');

    final jwtBuildDir = Directory('${circomDir.path}/build/jwt/jwt_js');
    final showBuildDir = Directory('${circomDir.path}/build/show/show_js');
    await jwtBuildDir.create(recursive: true);
    await showBuildDir.create(recursive: true);

    // Decompress r1cs files — skip if already extracted (each is ~350MB).
    final compressedAssets = {
      'assets/circom/jwt.r1cs.gz': '${jwtBuildDir.path}/jwt.r1cs',
      'assets/circom/show.r1cs.gz': '${showBuildDir.path}/show.r1cs',
    };
    for (final entry in compressedAssets.entries) {
      final target = File(entry.value);
      if (!await target.exists()) {
        debugPrint('Decompressing ${entry.key}');
        final data = await rootBundle.load(entry.key);
        final decompressed = gzip.decode(data.buffer.asUint8List());
        await target.writeAsBytes(decompressed);
        debugPrint(
            '  → ${(decompressed.length / 1024 / 1024).toStringAsFixed(2)} MB');
      }
    }

    // Always overwrite input JSON files so stale cached versions from a
    // previous app install never cause witness synthesis mismatches.
    // jwt_input.json is used by prove_jwt; show_input.json by prove_show;
    // run_complete_benchmark derives both paths from documentsPath automatically.
    final inputAssets = {
      'assets/circom/jwt_input.json': [
        '${circomDir.path}/jwt_input.json',
      ],
      'assets/circom/show_input.json': [
        '${circomDir.path}/show_input.json',
      ],
    };
    for (final entry in inputAssets.entries) {
      final data = await rootBundle.load(entry.key);
      final bytes = data.buffer.asUint8List();
      for (final dest in entry.value) {
        await File(dest).writeAsBytes(bytes);
        debugPrint('Wrote ${entry.key} → $dest');
      }
    }
  } catch (e) {
    debugPrint('Error copying assets: $e');
  }
}

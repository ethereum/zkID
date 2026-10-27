import 'dart:convert';
import 'dart:io';

import 'package:mopro_flutter_bindings/src/rust/third_party/openac_mobile_app.dart'
    show
        currentRssKb,
        deviceProfile,
        loadPrepareKey,
        loadPrepareReblindData,
        loadShowKey,
        memAvailableKb,
        peakRssKb,
        presentLoaded,
        provePrepareLoaded,
        proveShowLoaded,
        resetPeakRss,
        stageFile,
        zkErrorMessage,
        ZkProofError;
import 'package:openac/assets.dart';
import 'package:path_provider/path_provider.dart';

import 'bench_common.dart';

// Files the host pushes to /sdcard/zkbench/<package>/ (the shell can write there
// on every API level; the app reads it through MANAGE_EXTERNAL_STORAGE, which the
// runner grants with appops after install).
const _benchDir = '/sdcard/zkbench/com.openac.app';

const _prepareKey = '2k_prepare_proving.key';
const _showKey = '2k_show_proving.key';
const _prepareInstance = '2k_prepare_instance.bin';
const _prepareWitness = '2k_prepare_witness.bin';
const _sharedBlinds = '2k_shared_blinds.bin';

const _stepFiles = {
  'prepare': [_prepareKey],
  'show': [_showKey],
  'present': [
    _prepareKey,
    _showKey,
    _prepareInstance,
    _prepareWitness,
    _sharedBlinds
  ],
};

/// Where the host writes bench_config.json before `am instrument`.
Future<String> benchConfigPath() async => '$_benchDir/bench_config.json';

/// Proofs and instances of the last iteration land here, for the
/// host to pull and verify (scripts/verify_device_proofs.sh).
Future<String> _outDir() async => '$_benchDir/out';

const _outStems = {
  'prepare': ['prepare'],
  'show': ['show'],
  'present': ['present_prepare', 'present_show'],
};

Future<String> _pushedDir() async => _benchDir;

Future<void> _error(String step, int iter, Object e) async => logError(
    'OPENAC_',
    {'step': step, 'iter': iter},
    e is ZkProofError ? await zkErrorMessage(e: e) : e);

bool _emit(String kind, String step, int iter, Map<String, Object?> obj) =>
    logMarker('OPENAC_$kind', obj,
        errorPrefix: 'OPENAC_', errorFields: {'step': step, 'iter': iter});

/// What one iteration reports: one ITER row per entry, plus the proof size.
class _Iteration {
  final List<Map<String, Object?>> rows;
  final Map<String, Object?> sizes;
  _Iteration(this.rows, this.sizes);
}

/// Runs bench_config.json and prints the contract's marker lines. Returns the
/// number of ITER lines printed.
Future<int> runContractBench() async {
  final cfg = jsonDecode(await File(await benchConfigPath()).readAsString())
      as Map<String, Object?>;
  final steps = (cfg['steps']! as List).cast<String>();
  final warmIters = cfg['warm_iters'] as int? ?? 5;
  final cooldownMs = cfg['cooldown_ms'] as int? ?? 10000;
  final docs = await prepareInputsOnly();

  final profile = jsonDecode(await deviceProfile()) as Map<String, Object?>;
  logMarker(
      'OPENAC_DEVICE',
      {
        ...profile,
        'model': profile['product_model'],
        'sdk': int.tryParse('${profile['android_sdk']}') ?? 0,
        'threads': profile['rayon_default_threads'],
      },
      errorPrefix: 'OPENAC_',
      errorFields: {'step': '-', 'iter': -1});

  final staging = Directory(
      '${(await getApplicationSupportDirectory()).path}/openac_bench');
  var ok = 0;
  var errors = 0;
  var processCold = true;
  for (final step in steps) {
    final files = _stepFiles[step];
    if (files == null) {
      errors++;
      await _error(step, -1, 'unknown step');
      continue;
    }
    int stageMs;
    try {
      final sw = Stopwatch()..start();
      for (final f in files) {
        await stageFile(
            src: '${await _pushedDir()}/$f', dest: '${staging.path}/$f');
      }
      stageMs = sw.elapsedMilliseconds;
    } catch (e) {
      errors++;
      await _error(step, -1, e);
      continue;
    }

    // A failed run must not leave a previous run's proofs to be pulled and verified.
    final out = await _outDir();
    for (final stem in _outStems[step]!) {
      for (final ext in ['proof', 'instance']) {
        final f = File('$out/$stem.$ext');
        if (await f.exists()) await f.delete();
      }
    }

    for (var iter = 0; iter <= warmIters; iter++) {
      if (iter > 0 || !processCold) {
        await Future<void>.delayed(Duration(milliseconds: cooldownMs));
      }
      try {
        final cold = iter == 0;
        final result = switch (step) {
          'prepare' => await _prepare(docs, staging.path, out, cold),
          'show' => await _show(docs, staging.path, out, cold),
          _ => await _present(docs, staging.path, out, cold),
        };
        if (cold) {
          _emit('SIZES', step, iter, {
            'step': step,
            ...result.sizes,
            for (final f in files)
              '${f.replaceAll(RegExp(r'^2k_|\.(key|bin)$'), '')}_bytes':
                  await File('${staging.path}/$f').length(),
            'stage_ms': stageMs,
            'out_files': [
              for (final stem in _outStems[step]!)
                for (final ext in ['proof', 'instance']) 'out/$stem.$ext'
            ],
          });
        }
        for (final row in result.rows) {
          final line = {
            'step': row['step'],
            'iter': iter,
            'phase': cold ? 'cold' : 'warm',
            // Later steps of a multi-step run start with a warm process.
            'process_cold': cold && processCold,
            ...row..remove('step'),
          };
          if (_emit('ITER', step, iter, line)) {
            ok++;
          } else {
            errors++;
          }
        }
      } catch (e) {
        errors++;
        await _error(step, iter, e);
        break;
      }
    }
    processCold = false;
  }

  printLine('OPENAC_DONE ${jsonEncode({'ok': ok, 'errors': errors})}');
  return ok;
}

Future<_Iteration> _prepare(
    String docs, String staging, String out, bool cold) async {
  final avail = toInt(await memAvailableKb());
  final base = toInt(await currentRssKb());
  final perStep = await resetPeakRss();
  final sw = Stopwatch()..start();
  var loadMs = 0;
  if (cold) loadMs = toInt(await loadPrepareKey(path: '$staging/$_prepareKey'));
  final r = await provePrepareLoaded(documentsPath: docs, outDir: out);
  final totalMs = sw.elapsedMilliseconds;
  return _Iteration([
    {
      'step': 'prepare',
      'load_ms': loadMs,
      'witness_ms': toInt(r.witnessMs),
      'prove_ms': toInt(r.proveMs),
      'total_ms': totalMs,
      'base_rss_kb': base,
      'peak_rss_kb': toInt(await peakRssKb()),
      'mem_available_kb_before': avail,
      if (!perStep) 'rss_per_step': false,
    }
  ], {
    'proof_bytes': toInt(r.proofBytes)
  });
}

Future<_Iteration> _show(
    String docs, String staging, String out, bool cold) async {
  final avail = toInt(await memAvailableKb());
  final base = toInt(await currentRssKb());
  final perStep = await resetPeakRss();
  final sw = Stopwatch()..start();
  var loadMs = 0;
  if (cold) loadMs = toInt(await loadShowKey(path: '$staging/$_showKey'));
  final r = await proveShowLoaded(documentsPath: docs, outDir: out);
  final totalMs = sw.elapsedMilliseconds;
  return _Iteration([
    {
      'step': 'show',
      'load_ms': loadMs,
      'prove_ms': toInt(r.proveMs),
      'total_ms': totalMs,
      'base_rss_kb': base,
      'peak_rss_kb': toInt(await peakRssKb()),
      'mem_available_kb_before': avail,
      if (!perStep) 'rss_per_step': false,
    }
  ], {
    'proof_bytes': toInt(r.proofBytes)
  });
}

/// One presentation as the SDK's present() runs it: Show prove, then reblind
/// of the Prepare and Show proofs. Cold loads both proving keys, the Prepare
/// instance and witness, and the shared blinds inside the timed region.
Future<_Iteration> _present(
    String docs, String staging, String out, bool cold) async {
  final avail = toInt(await memAvailableKb());
  final base = toInt(await currentRssKb());
  final perStep = await resetPeakRss();
  final sw = Stopwatch()..start();
  var loadMs = 0;
  var loadPeakKb = 0;
  if (cold) {
    loadMs += toInt(await loadPrepareKey(path: '$staging/$_prepareKey'));
    loadMs += toInt(await loadShowKey(path: '$staging/$_showKey'));
    loadMs += toInt(await loadPrepareReblindData(
        instancePath: '$staging/$_prepareInstance',
        witnessPath: '$staging/$_prepareWitness',
        sharedBlindsPath: '$staging/$_sharedBlinds'));
    loadPeakKb = toInt(await peakRssKb());
  }
  final r = await presentLoaded(documentsPath: docs, outDir: out);
  final totalMs = sw.elapsedMilliseconds;

  Map<String, Object?> sub(String step, BigInt ms, BigInt peakKb) => {
        'step': step,
        'load_ms': 0,
        'prove_ms': toInt(ms),
        'total_ms': toInt(ms),
        'base_rss_kb': base,
        'peak_rss_kb': toInt(peakKb),
        'mem_available_kb_before': avail,
        if (!perStep || !r.rssPerStep) 'rss_per_step': false,
      };
  final peak =
      toInt(r.peakRssKb) > loadPeakKb ? toInt(r.peakRssKb) : loadPeakKb;
  return _Iteration([
    sub('show_prove', r.showProveMs, r.peakRssShowProveKb),
    sub('prepare_reblind', r.prepareReblindMs, r.peakRssPrepareReblindKb),
    sub('show_reblind', r.showReblindMs, r.peakRssShowReblindKb),
    {
      ...sub('present_total', r.totalMs, BigInt.from(peak)),
      'load_ms': loadMs,
      'total_ms': totalMs,
    },
  ], {
    'proof_bytes': toInt(r.prepareProofBytes) + toInt(r.showProofBytes),
    'prepare_proof_bytes': toInt(r.prepareProofBytes),
    'show_proof_bytes': toInt(r.showProofBytes),
  });
}

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:mopro_flutter_bindings/src/rust/frb_generated.dart';
import 'package:mopro_flutter_bindings/src/rust/third_party/openac_mobile_app.dart'
    show
        BenchmarkResults,
        deviceProfile,
        generateSharedBlinds,
        proveJwt,
        proveShow,
        reblindJwt,
        reblindShow,
        runCompleteBenchmarkWith,
        setupJwtKeys,
        setupShowKeys,
        verifyJwt,
        verifyShow;
import 'package:openac/assets.dart';

import 'bench_common.dart';
import 'contract_bench.dart';

// Set by build_ftl_apks.sh only. Without it this test runs the contract harness
// and never falls back to the on-device-keygen configs below.
const _legacy = bool.fromEnvironment('BENCH_LEGACY');

const _warmup = int.fromEnvironment('BENCH_WARMUP', defaultValue: 1);
const _itersA = int.fromEnvironment('BENCH_ITERS_A', defaultValue: 5);
const _itersB = int.fromEnvironment('BENCH_ITERS_B', defaultValue: 3);
const _itersP = int.fromEnvironment('BENCH_ITERS_P', defaultValue: 3);
const _cooldownS = int.fromEnvironment('BENCH_COOLDOWN_S', defaultValue: 20);

void _logError(String config, int iter, Object error) =>
    logError('OPENAC_', {'config': config, 'iter': iter}, error);

bool _log(String marker, Map<String, Object?> obj,
        {String config = '-', int iter = -1}) =>
    logMarker(marker, obj,
        errorPrefix: 'OPENAC_', errorFields: {'config': config, 'iter': iter});

Map<String, Object?> _metrics(BenchmarkResults r) => {
      'jwt_setup_ms': toInt(r.jwtSetupMs),
      'show_setup_ms': toInt(r.showSetupMs),
      'generate_blinds_ms': toInt(r.generateBlindsMs),
      'prove_jwt_ms': toInt(r.proveJwtMs),
      'reblind_jwt_ms': toInt(r.reblindJwtMs),
      'prove_show_ms': toInt(r.proveShowMs),
      'reblind_show_ms': toInt(r.reblindShowMs),
      'verify_jwt_ms': toInt(r.verifyJwtMs),
      'verify_show_ms': toInt(r.verifyShowMs),
      'peak_rss_jwt_setup_kb': toInt(r.peakRssJwtSetupKb),
      'peak_rss_show_setup_kb': toInt(r.peakRssShowSetupKb),
      'peak_rss_generate_blinds_kb': toInt(r.peakRssGenerateBlindsKb),
      'peak_rss_prove_jwt_kb': toInt(r.peakRssProveJwtKb),
      'peak_rss_reblind_jwt_kb': toInt(r.peakRssReblindJwtKb),
      'peak_rss_prove_show_kb': toInt(r.peakRssProveShowKb),
      'peak_rss_reblind_show_kb': toInt(r.peakRssReblindShowKb),
      'peak_rss_verify_jwt_kb': toInt(r.peakRssVerifyJwtKb),
      'peak_rss_verify_show_kb': toInt(r.peakRssVerifyShowKb),
      'rss_per_step': r.rssPerStep,
    };

Map<String, Object?> _sizes(String config, BenchmarkResults r) => {
      'config': config,
      'jwt_proving_key_bytes': toInt(r.jwtProvingKeyBytes),
      'jwt_verifying_key_bytes': toInt(r.jwtVerifyingKeyBytes),
      'show_proving_key_bytes': toInt(r.showProvingKeyBytes),
      'show_verifying_key_bytes': toInt(r.showVerifyingKeyBytes),
      'jwt_proof_bytes': toInt(r.jwtProofBytes),
      'show_proof_bytes': toInt(r.showProofBytes),
      'jwt_witness_bytes': toInt(r.jwtWitnessBytes),
      'show_witness_bytes': toInt(r.showWitnessBytes),
    };

class _Config {
  final String name;
  final bool pinBigCores;
  final int warmups;
  final int iters;
  const _Config(this.name, this.pinBigCores, this.warmups, this.iters);
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('openac android benchmark', (tester) async {
    await RustLib.init();

    // The contract harness (keys pushed from the host, no setup) unless the
    // build opted into the Firebase Test Lab configs below.
    if (!_legacy) {
      final r = await runContractBench();
      expect(r.errors, 0, reason: 'OPENAC_ERROR lines were printed');
      expect(r.ok, greaterThan(0), reason: 'no iteration succeeded');
      return;
    }

    final docs = await prepareAssets();

    _log('OPENAC_DEVICE',
        jsonDecode(await deviceProfile()) as Map<String, Object?>);

    var first = true;
    var okP = 0;
    var errors = 0;

    // Config P: the production path, measured per step. Setup and asset
    // decompression run in this same process first, so the residue they leave
    // shows up in base RSS; peak RSS is the high-water mark during each call.
    if (_itersP > 0) {
      var setupOk = true;
      try {
        await setupJwtKeys(documentsPath: docs);
        await setupShowKeys(documentsPath: docs);
        await generateSharedBlinds(documentsPath: docs);
      } catch (e) {
        setupOk = false;
        errors++;
        _logError('P', -1, e);
      }
      for (var iter = 0; setupOk && iter < _itersP; iter++) {
        if (!first) {
          await Future<void>.delayed(const Duration(seconds: _cooldownS));
        }
        first = false;
        try {
          final pj = await probe(() => proveJwt(documentsPath: docs));
          final rj = await probe(() => reblindJwt(documentsPath: docs));
          final ps = await probe(() => proveShow(documentsPath: docs));
          final rs = await probe(() => reblindShow(documentsPath: docs));
          var vjMs = 0;
          final vj = await probe(() async {
            final sw = Stopwatch()..start();
            final ok = await verifyJwt(documentsPath: docs);
            vjMs = sw.elapsedMilliseconds;
            return ok;
          });
          var vsMs = 0;
          final vs = await probe(() async {
            final sw = Stopwatch()..start();
            final ok = await verifyShow(documentsPath: docs);
            vsMs = sw.elapsedMilliseconds;
            return ok;
          });
          if (!vj.out || !vs.out) throw StateError('verify returned false');
          final steps = {
            'prove_jwt': pj,
            'reblind_jwt': rj,
            'prove_show': ps,
            'reblind_show': rs,
            'verify_jwt': vj,
            'verify_show': vs,
          };
          final logged = _log(
              'OPENAC_PROD',
              {
                'iter': iter,
                'prove_jwt_ms': toInt(pj.out.proveMs),
                'reblind_jwt_ms': toInt(rj.out.proveMs),
                'prove_show_ms': toInt(ps.out.proveMs),
                'reblind_show_ms': toInt(rs.out.proveMs),
                // Wall time of the Dart call: includes key/proof load and FFI.
                'verify_jwt_wall_ms': vjMs,
                'verify_show_wall_ms': vsMs,
                for (final e in steps.entries) ...{
                  'base_rss_${e.key}_kb': e.value.baseKb,
                  'peak_rss_${e.key}_kb': e.value.peakKb,
                },
                'rss_per_step': steps.values.every((p) => p.perStep),
              },
              config: 'P',
              iter: iter);
          if (logged) {
            okP++;
          } else {
            errors++;
          }
        } catch (e) {
          errors++;
          _logError('P', iter, e);
        }
      }
    }

    const configs = [
      _Config('A', false, _warmup, _itersA),
      _Config('B', true, 0, _itersB),
    ];
    final ok = {'A': 0, 'B': 0};

    for (final c in configs) {
      var sizesLogged = false;
      for (var iter = 0; iter < c.warmups + c.iters; iter++) {
        if (!first) {
          await Future<void>.delayed(const Duration(seconds: _cooldownS));
        }
        first = false;
        try {
          final r = await runCompleteBenchmarkWith(
            documentsPath: docs,
            numThreads: 0,
            pinBigCores: c.pinBigCores,
          );
          if (!sizesLogged) {
            _log('OPENAC_SIZES', _sizes(c.name, r), config: c.name, iter: iter);
            sizesLogged = true;
          }
          final logged = _log(
              'OPENAC_BENCH',
              {
                'config': c.name,
                'iter': iter,
                'warmup': iter < c.warmups,
                'num_threads': 0,
                'pin_big_cores': c.pinBigCores,
                'pool_threads': r.poolThreads,
                'pinned_threads': r.pinnedThreads,
                'pinned_threads_end': r.pinnedThreadsEnd,
                ..._metrics(r),
              },
              config: c.name,
              iter: iter);
          if (logged) {
            ok[c.name] = ok[c.name]! + 1;
          } else {
            errors++;
          }
        } catch (e) {
          errors++;
          _logError(c.name, iter, e);
        }
      }
    }

    _log('OPENAC_DONE',
        {'ok_p': okP, 'ok_a': ok['A'], 'ok_b': ok['B'], 'errors': errors});
    expect(okP + ok['A']! + ok['B']!, greaterThan(0),
        reason: 'no iteration succeeded');
  }, timeout: Timeout.none);
}

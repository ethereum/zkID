import 'dart:convert';
import 'dart:io';

import 'package:mopro_flutter_bindings/mopro_flutter_bindings.dart' as rust;

import 'flow_backend.dart';
import 'flow_models.dart';

// Key file names mirror `paths::keys` in
// wallet-unit-poc/ecdsa-spartan2/src/paths.rs. Proving key first: it is the one
// the load step reads.
const _prepareKeyFiles = ['prepare_proving.key', 'prepare_verifying.key'];
const _showKeyFiles = ['show_proving.key', 'show_verifying.key'];

/// Which circuits need key setup.
class KeySetupPlan {
  const KeySetupPlan({required this.prepare, required this.show});

  final bool prepare;
  final bool show;

  bool get any => prepare || show;
}

/// A circuit needs setup when either of its key files is missing. A file that
/// exists but is truncated is not detected here; it surfaces as a load error.
KeySetupPlan planKeySetup(bool Function(String name) exists) => KeySetupPlan(
      prepare: !_prepareKeyFiles.every(exists),
      show: !_showKeyFiles.every(exists),
    );

/// A failed proving-key load is retried with a fresh setup only if setup has
/// not already run for that circuit in this call; redoing it would repeat the
/// same result.
bool retryLoadAfterSetup({required bool setupRanThisCall}) => !setupRanThisCall;

/// [FlowBackend] over the generated Rust bindings.
class RustFlowBackend implements FlowBackend {
  RustFlowBackend(this.docsPath);

  final String docsPath;

  String get _keysDir => '$docsPath/keys';

  @override
  Future<KeysInfo> ensureKeys() => _guard(() async {
        final plan =
            planKeySetup((name) => File('$_keysDir/$name').existsSync());
        var setupRan = plan.any;
        final setupWatch = Stopwatch()..start();
        if (plan.prepare) await _setup(_prepareKeyFiles, rust.setupJwtKeys);
        if (plan.show) await _setup(_showKeyFiles, rust.setupShowKeys);
        var setupMs = setupWatch.elapsedMilliseconds;

        final loadWatch = Stopwatch();
        Future<void> load(
          List<String> files,
          bool setupRanThisCall,
          Future<BigInt> Function({required String path}) loadKey,
          Future<String> Function({required String documentsPath}) setup,
        ) async {
          final path = '$_keysDir/${files.first}';
          loadWatch.start();
          try {
            await loadKey(path: path);
          } on rust.ZkProofError catch (first) {
            loadWatch.stop();
            if (!retryLoadAfterSetup(setupRanThisCall: setupRanThisCall)) {
              rethrow;
            }
            // The key may be truncated from an earlier interrupted setup:
            // drop it, redo setup once, and load again.
            setupRan = true;
            setupWatch
              ..reset()
              ..start();
            await _setup(files, setup);
            setupMs += setupWatch.elapsedMilliseconds;
            loadWatch.start();
            try {
              await loadKey(path: path);
            } on rust.ZkProofError catch (second) {
              throw StateError('${await rust.zkErrorMessage(e: first)}; '
                  'after re-running setup: ${await rust.zkErrorMessage(e: second)}');
            }
          }
          loadWatch.stop();
        }

        await load(_prepareKeyFiles, plan.prepare, rust.loadPrepareKey,
            rust.setupJwtKeys);
        await load(
            _showKeyFiles, plan.show, rust.loadShowKey, rust.setupShowKeys);
        return KeysInfo(
          setupRan: setupRan,
          setupMs: setupMs,
          loadMs: loadWatch.elapsedMilliseconds,
        );
      });

  Future<void> _setup(
    List<String> files,
    Future<String> Function({required String documentsPath}) setup,
  ) async {
    for (final name in files) {
      final f = File('$_keysDir/$name');
      if (f.existsSync()) await f.delete();
    }
    await setup(documentsPath: docsPath);
  }

  @override
  Future<PrepareOutcome> prepare() => _guard(() async {
        final r = await rust.flowPrepare(
          documentsPath: docsPath,
          inputPath: '$docsPath/jwt_input.json',
        );
        return PrepareOutcome(
          witnessMs: r.witnessMs.toInt(),
          proveMs: r.proveMs.toInt(),
          proofBytes: r.proofBytes.toInt(),
          instanceBytes: r.instanceBytes.toInt(),
          proofFingerprint: r.proofFingerprint,
          commWShared: r.commWShared,
        );
      });

  @override
  Future<Presentation> present(FlowRequest request) => _guard(() async {
        final file = File('$docsPath/flow_show_input_${request.id}.json');
        await file.writeAsString(jsonEncode(request.showInput));
        final r = await rust.flowPresent(
          documentsPath: docsPath,
          showInputPath: file.path,
        );
        return Presentation(
          requestId: request.id,
          presentedAt: DateTime.now(),
          prepareProof: r.prepareProof,
          showProof: r.showProof,
          prepareFingerprint: r.prepareFingerprint,
          showFingerprint: r.showFingerprint,
          prepareCommWShared: r.prepareCommWShared,
          showCommWShared: r.showCommWShared,
          showProveMs: r.showProveMs.toInt(),
          prepareReblindMs: r.prepareReblindMs.toInt(),
          showReblindMs: r.showReblindMs.toInt(),
          totalMs: r.totalMs.toInt(),
        );
      });

  @override
  Future<VerifyOutcome> verify(Presentation p, FlowRequest against) =>
      _guard(() async {
        final r = await rust.flowVerify(
          documentsPath: docsPath,
          prepareProof: p.prepareProof,
          showProof: p.showProof,
          expected: rust.FlowExpectedStatement(
            preparePublicValues: against.preparePublicValues,
            showStatement: against.showStatement,
          ),
        );
        return VerifyOutcome(
          valid: r.valid,
          expressionResult: r.expressionResult,
          proofsLinked: r.proofsLinked,
          issuerTrusted: r.issuerTrusted,
          normalizationMatches: r.normalizationMatches,
          nonceMatches: r.nonceMatches,
          policyMatches: r.policyMatches,
          issuerKeyX: r.issuerKeyX,
          issuerKeyY: r.issuerKeyY,
          vkLoadMs: r.vkLoadMs.toInt(),
          verifyMs: r.verifyMs.toInt(),
          failure: r.failure,
        );
      });

  @override
  Future<void> unload() => rust.flowUnload();

  /// Rust errors arrive as opaque handles; turn them into text.
  Future<T> _guard<T>(Future<T> Function() body) async {
    try {
      return await body();
    } on rust.ZkProofError catch (e) {
      throw StateError(await rust.zkErrorMessage(e: e));
    }
  }
}

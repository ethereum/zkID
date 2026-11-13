import 'dart:async';
import 'dart:typed_data';

import 'package:openac/flow/flow_backend.dart';
import 'package:openac/flow/flow_models.dart';

/// Mimics the Rust checks well enough for the scenarios in the sample bundle:
/// a proof made for request X only verifies against X, and request D carries
/// a different trusted issuer.
class FakeFlowBackend implements FlowBackend {
  final calls = <String>[];
  int unloadCount = 0;
  int _presentations = 0;

  /// While set, every call waits on it; lets tests observe the busy state.
  Completer<void>? gate;

  /// While set, [unload] waits on it.
  Completer<void>? unloadGate;

  /// The next call of this name throws once.
  String? failNext;

  Future<void> _enter(String name) async {
    calls.add(name);
    await gate?.future;
    if (failNext == name) {
      failNext = null;
      throw StateError('$name failed');
    }
  }

  @override
  Future<KeysInfo> ensureKeys() async {
    await _enter('ensureKeys');
    return const KeysInfo(setupRan: true, setupMs: 1200, loadMs: 300);
  }

  @override
  Future<PrepareOutcome> prepare() async {
    await _enter('prepare');
    return const PrepareOutcome(
      witnessMs: 400,
      proveMs: 5000,
      proofBytes: 123456,
      instanceBytes: 789,
      proofFingerprint: 'aaaaaaaaaaaaaaaa',
      commWShared: 'c0ffee',
    );
  }

  @override
  Future<Presentation> present(FlowRequest request) async {
    await _enter('present');
    final n = ++_presentations;
    final tag = n.toString().padLeft(2, '0');
    return Presentation(
      requestId: request.id,
      presentedAt: DateTime(2026, 11, 12, 10, n),
      prepareProof: Uint8List(8),
      showProof: Uint8List(4),
      prepareFingerprint: 'prep00000000000$tag',
      showFingerprint: 'show00000000000$tag',
      prepareCommWShared: 'cw00$tag',
      showCommWShared: 'cw00$tag',
      showProveMs: 900,
      prepareReblindMs: 50,
      showReblindMs: 40,
      totalMs: 1000,
    );
  }

  @override
  Future<VerifyOutcome> verify(Presentation p, FlowRequest against) async {
    await _enter('verify');
    final nonceMatches = p.requestId == against.id;
    final issuerTrusted = against.id != 'D';
    final valid = nonceMatches && issuerTrusted;
    return VerifyOutcome(
      valid: valid,
      expressionResult: against.expectedExpressionResult,
      proofsLinked: true,
      issuerTrusted: issuerTrusted,
      normalizationMatches: true,
      nonceMatches: nonceMatches,
      policyMatches: nonceMatches,
      issuerKeyX: '11',
      issuerKeyY: '22',
      vkLoadMs: 10,
      verifyMs: 20,
      failure: valid
          ? null
          : (nonceMatches ? 'issuer not trusted' : 'nonce mismatch'),
    );
  }

  @override
  Future<void> unload() async {
    unloadCount++;
    await unloadGate?.future;
  }
}

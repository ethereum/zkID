import 'dart:typed_data';

import 'flow_models.dart';

/// The seam between the flow UI and the Rust prover. Keys are held between
/// calls, so [unload] must run before anything else touches the key files.
abstract class FlowBackend {
  /// Loads both proving keys. Setup runs for a circuit when either of its key
  /// files is missing, or when its proving key fails to load.
  Future<KeysInfo> ensureKeys();

  /// Proves the Prepare circuit from `{docs}/jwt_input.json`.
  Future<PrepareOutcome> prepare();

  /// Proves Show for [request], then reblinds both proofs with shared
  /// randomness.
  Future<Presentation> present(FlowRequest request);

  /// Checks [p] against what [against] expects.
  Future<VerifyOutcome> verify(Presentation p, FlowRequest against);

  Future<void> unload();
}

/// Used when the app cannot start the Rust prover, for example because the
/// circuit assets failed to prepare. Every call fails with [reason], which the
/// flow screen shows.
class UnavailableFlowBackend implements FlowBackend {
  const UnavailableFlowBackend(this.reason);

  final String reason;

  Future<T> _fail<T>() => Future.error(UnsupportedError(reason));

  @override
  Future<KeysInfo> ensureKeys() => _fail();

  @override
  Future<PrepareOutcome> prepare() => _fail();

  @override
  Future<Presentation> present(FlowRequest request) => _fail();

  @override
  Future<VerifyOutcome> verify(Presentation p, FlowRequest against) => _fail();

  @override
  Future<void> unload() async {}
}

class KeysInfo {
  final bool setupRan;
  final int setupMs;
  final int loadMs;

  const KeysInfo({
    required this.setupRan,
    required this.setupMs,
    required this.loadMs,
  });
}

class PrepareOutcome {
  final int witnessMs;
  final int proveMs;
  final int proofBytes;
  final int instanceBytes;
  final String proofFingerprint;
  final String commWShared;

  const PrepareOutcome({
    required this.witnessMs,
    required this.proveMs,
    required this.proofBytes,
    required this.instanceBytes,
    required this.proofFingerprint,
    required this.commWShared,
  });
}

class Presentation {
  final String requestId;
  final DateTime presentedAt;
  final Uint8List prepareProof;
  final Uint8List showProof;
  final String prepareFingerprint;
  final String showFingerprint;
  final String prepareCommWShared;
  final String showCommWShared;
  final int showProveMs;
  final int prepareReblindMs;
  final int showReblindMs;
  final int totalMs;

  const Presentation({
    required this.requestId,
    required this.presentedAt,
    required this.prepareProof,
    required this.showProof,
    required this.prepareFingerprint,
    required this.showFingerprint,
    required this.prepareCommWShared,
    required this.showCommWShared,
    required this.showProveMs,
    required this.prepareReblindMs,
    required this.showReblindMs,
    required this.totalMs,
  });
}

class VerifyOutcome {
  final bool valid;
  final bool expressionResult;
  final bool proofsLinked;
  final bool issuerTrusted;
  final bool normalizationMatches;
  final bool nonceMatches;
  final bool policyMatches;
  final String issuerKeyX;
  final String issuerKeyY;
  final int vkLoadMs;
  final int verifyMs;
  final String? failure;

  const VerifyOutcome({
    required this.valid,
    required this.expressionResult,
    required this.proofsLinked,
    required this.issuerTrusted,
    required this.normalizationMatches,
    required this.nonceMatches,
    required this.policyMatches,
    required this.issuerKeyX,
    required this.issuerKeyY,
    required this.vkLoadMs,
    required this.verifyMs,
    this.failure,
  });
}

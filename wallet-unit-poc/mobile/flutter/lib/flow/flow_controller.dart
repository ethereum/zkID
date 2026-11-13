import 'dart:async';

import 'package:flutter/foundation.dart';

import 'flow_backend.dart';
import 'flow_models.dart';

enum FlowStep { keys, credential, prepare, request, present, verify }

enum StepStatus { disabled, active, running, done, error }

class FlowController extends ChangeNotifier {
  FlowController({
    required this.backend,
    required this.loadBundle,
    this.sharedBusy,
  });

  final FlowBackend backend;
  final Future<FlowBundle> Function() loadBundle;

  /// Mirrors [busy] so the app shell can lock navigation while Rust runs.
  final ValueNotifier<bool>? sharedBusy;

  final _status = {for (final s in FlowStep.values) s: StepStatus.disabled};
  final _errors = <FlowStep, String>{};
  bool _busy = false;
  bool _disposed = false;

  FlowBundle? bundle;
  String? bundleError;
  FlowScenario? _scenario;

  KeysInfo? keys;
  PrepareOutcome? prepared;
  Presentation? presentation;

  /// The presentation [presentation] replaced, for the unlinkability view.
  Presentation? previousPresentation;
  VerifyOutcome? verifyOutcome;

  bool get busy => _busy;
  StepStatus status(FlowStep s) => _status[s]!;
  String? error(FlowStep s) => _errors[s];

  FlowScenario get scenario => _scenario!;
  FlowRequest get presentRequest => bundle!.request(scenario.presentFor);
  FlowRequest get verifyRequest => bundle!.request(scenario.verifyAgainst);

  Verdict? get verdict => verifyOutcome == null
      ? null
      : Verdict.of(
          valid: verifyOutcome!.valid,
          expressionResult: verifyOutcome!.expressionResult);
  bool? get matchesExpected =>
      verdict == null ? null : verdict == scenario.expect.verdict;

  bool canRun(FlowStep s) =>
      !_busy &&
      switch (status(s)) {
        StepStatus.active || StepStatus.error => true,
        StepStatus.done => s == FlowStep.present || s == FlowStep.verify,
        _ => false,
      };

  Future<void> load() async {
    try {
      bundle = await loadBundle();
      _scenario = bundle!.scenarios.first;
      _status[FlowStep.keys] = StepStatus.active;
    } catch (e) {
      bundleError = e.toString();
    }
    _notify();
  }

  Future<void> runKeys() => _run(FlowStep.keys, () async {
        keys = await backend.ensureKeys();
        _status[FlowStep.credential] = StepStatus.active;
      });

  /// The credential step holds no backend call; it only shows what the
  /// wallet would normally hand over.
  void inspectCredential() {
    if (status(FlowStep.credential) != StepStatus.active) return;
    _status[FlowStep.credential] = StepStatus.done;
    _status[FlowStep.prepare] = StepStatus.active;
    _notify();
  }

  Future<void> runPrepare() => _run(FlowStep.prepare, () async {
        prepared = await backend.prepare();
        _status[FlowStep.request] = StepStatus.done;
        _resetPresentation();
      });

  void selectScenario(String id) {
    if (_busy || id == scenario.id) return;
    _scenario = bundle!.scenarios.firstWhere((s) => s.id == id);
    if (status(FlowStep.request) == StepStatus.done) _resetPresentation();
    _notify();
  }

  Future<void> runPresent() => _run(FlowStep.present, () async {
        final next = await backend.present(presentRequest);
        previousPresentation = presentation;
        presentation = next;
        verifyOutcome = null;
        _errors.remove(FlowStep.verify);
        _status[FlowStep.verify] = StepStatus.active;
      });

  Future<void> runVerify() => _run(FlowStep.verify, () async {
        verifyOutcome = await backend.verify(presentation!, verifyRequest);
      });

  void _resetPresentation() {
    presentation = null;
    previousPresentation = null;
    verifyOutcome = null;
    _errors.remove(FlowStep.present);
    _errors.remove(FlowStep.verify);
    _status[FlowStep.present] = StepStatus.active;
    _status[FlowStep.verify] = StepStatus.disabled;
  }

  Future<void> _run(FlowStep step, Future<void> Function() body) async {
    if (!canRun(step)) return;
    _setBusy(true);
    _status[step] = StepStatus.running;
    _errors.remove(step);
    _notify();
    try {
      await body();
      _status[step] = StepStatus.done;
    } catch (e) {
      _status[step] = StepStatus.error;
      _errors[step] = e.toString();
    }
    _setBusy(false);
  }

  void _setBusy(bool v) {
    _busy = v;
    sharedBusy?.value = v;
    _notify();
  }

  void _notify() {
    if (!_disposed) notifyListeners();
  }

  @override
  void dispose() {
    _disposed = true;
    unawaited(backend.unload());
    super.dispose();
  }
}

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:openac/flow/flow_controller.dart';
import 'package:openac/flow/flow_models.dart';

import 'fake_flow_backend.dart';

Future<FlowBundle> sampleBundle() async => FlowBundle.fromJson(
    jsonDecode(File('test/fixtures/sample_bundle.json').readAsStringSync())
        as Map<String, dynamic>);

Future<FlowController> readyController(FakeFlowBackend backend,
    {ValueNotifier<bool>? busy}) async {
  final c = FlowController(
      backend: backend, loadBundle: sampleBundle, sharedBusy: busy);
  await c.load();
  return c;
}

Future<void> upToRequest(FlowController c) async {
  await c.runKeys();
  await c.runPrepare();
}

Future<void> runScenario(FlowController c, String id) async {
  c.selectScenario(id);
  await c.runPresent();
  await c.runVerify();
}

void main() {
  late FakeFlowBackend backend;

  setUp(() => backend = FakeFlowBackend());

  test('starts with only the keys step active', () async {
    final c = await readyController(backend);
    expect(c.status(FlowStep.keys), StepStatus.active);
    for (final s in FlowStep.values.skip(1)) {
      expect(c.status(s), StepStatus.disabled);
    }
    expect(c.scenario.id, 'over18');
  });

  test('a failing bundle loader is reported, not thrown', () async {
    final c = FlowController(
        backend: backend,
        loadBundle: () async =>
            throw StateError('run scripts/prepare-assets.sh'));
    await c.load();
    expect(c.bundleError, contains('prepare-assets.sh'));
    expect(c.bundle, isNull);
  });

  test('happy path through all six steps', () async {
    final c = await readyController(backend);

    await c.runKeys();
    expect(c.status(FlowStep.keys), StepStatus.done);
    expect(c.keys!.setupRan, isTrue);
    expect(c.status(FlowStep.credential), StepStatus.done);
    expect(c.status(FlowStep.prepare), StepStatus.active);

    await c.runPrepare();
    expect(c.status(FlowStep.prepare), StepStatus.done);
    expect(c.prepared!.proofFingerprint, 'aaaaaaaaaaaaaaaa');
    expect(c.status(FlowStep.request), StepStatus.done);
    expect(c.status(FlowStep.present), StepStatus.active);

    await c.runPresent();
    expect(c.status(FlowStep.present), StepStatus.done);
    expect(c.presentation!.requestId, 'A');
    expect(c.status(FlowStep.verify), StepStatus.active);

    await c.runVerify();
    expect(c.status(FlowStep.verify), StepStatus.done);
    expect(c.verdict, Verdict.verified);
    expect(c.matchesExpected, isTrue);
    expect(backend.calls, ['ensureKeys', 'prepare', 'present', 'verify']);
  });

  for (final (id, verdict, matches) in [
    ('over18', Verdict.verified, true),
    ('policyFalse', Verdict.policyNotSatisfied, true),
    ('replay', Verdict.rejected, true),
    ('untrustedIssuer', Verdict.rejected, true),
  ]) {
    test('scenario $id ends $verdict and matches expected', () async {
      final c = await readyController(backend);
      await upToRequest(c);
      await runScenario(c, id);
      expect(c.verdict, verdict);
      expect(c.matchesExpected, matches);
    });
  }

  test('replay presents for A and verifies against C', () async {
    final c = await readyController(backend);
    await upToRequest(c);
    c.selectScenario('replay');
    await c.runPresent();
    expect(c.presentation!.requestId, 'A');
    await c.runVerify();
    expect(c.verifyOutcome!.nonceMatches, isFalse);
    expect(c.verifyOutcome!.failure, 'nonce mismatch');
  });

  test('present again keeps the previous fingerprints', () async {
    final c = await readyController(backend);
    await upToRequest(c);
    await runScenario(c, 'over18');
    final first = c.presentation!;

    await c.runPresent();
    expect(c.previousPresentation, same(first));
    expect(c.presentation!.showFingerprint, isNot(first.showFingerprint));
    expect(c.presentation!.prepareFingerprint, isNot(first.prepareFingerprint));
    expect(c.status(FlowStep.verify), StepStatus.active);
    expect(c.verifyOutcome, isNull);
  });

  test('changing the scenario resets present and verify', () async {
    final c = await readyController(backend);
    await upToRequest(c);
    await runScenario(c, 'over18');

    c.selectScenario('policyFalse');
    expect(c.status(FlowStep.present), StepStatus.active);
    expect(c.status(FlowStep.verify), StepStatus.disabled);
    expect(c.presentation, isNull);
    expect(c.previousPresentation, isNull);
    expect(c.verifyOutcome, isNull);
    expect(c.status(FlowStep.prepare), StepStatus.done);
  });

  test('a failed step errors, keeps the message, and can be retried', () async {
    final c = await readyController(backend);
    backend.failNext = 'ensureKeys';
    await c.runKeys();
    expect(c.status(FlowStep.keys), StepStatus.error);
    expect(c.error(FlowStep.keys), contains('ensureKeys failed'));
    expect(c.canRun(FlowStep.keys), isTrue);
    expect(c.busy, isFalse);

    await c.runKeys();
    expect(c.status(FlowStep.keys), StepStatus.done);
    expect(c.error(FlowStep.keys), isNull);
  });

  test('a failed verify errors and retries', () async {
    final c = await readyController(backend);
    await upToRequest(c);
    await c.runPresent();
    backend.failNext = 'verify';
    await c.runVerify();
    expect(c.status(FlowStep.verify), StepStatus.error);
    await c.runVerify();
    expect(c.verdict, Verdict.verified);
  });

  test('busy is set during a backend call and mirrored to the shell', () async {
    final shared = ValueNotifier(false);
    final c = await readyController(backend, busy: shared);
    backend.gate = Completer<void>();
    final run = c.runKeys();
    await Future<void>.delayed(Duration.zero);
    expect(c.busy, isTrue);
    expect(shared.value, isTrue);
    expect(c.status(FlowStep.keys), StepStatus.running);
    expect(c.canRun(FlowStep.keys), isFalse);

    backend.gate!.complete();
    await run;
    expect(c.busy, isFalse);
    expect(shared.value, isFalse);
  });

  test('actions are ignored while busy', () async {
    final c = await readyController(backend);
    backend.gate = Completer<void>();
    final run = c.runKeys();
    await Future<void>.delayed(Duration.zero);
    await c.runKeys();
    backend.gate!.complete();
    await run;
    expect(backend.calls, ['ensureKeys']);
  });

  test('dispose unloads the backend', () async {
    final c = await readyController(backend);
    c.dispose();
    expect(backend.unloadCount, 1);
  });
}

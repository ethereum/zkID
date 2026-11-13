import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:openac/flow/flow_backend.dart';
import 'package:openac/flow/rust_flow_backend.dart';

void main() {
  KeySetupPlan planWithout(Set<String> missing) =>
      planKeySetup((name) => !missing.contains(name));

  test('nothing is set up when all four key files exist', () {
    final plan = planWithout({});
    expect(plan.prepare, isFalse);
    expect(plan.show, isFalse);
    expect(plan.any, isFalse);
  });

  test('a missing Prepare file sets up only Prepare', () {
    final plan = planWithout({'prepare_proving.key'});
    expect(plan.prepare, isTrue);
    expect(plan.show, isFalse);
  });

  test('a missing Show file sets up only Show', () {
    final plan = planWithout({'show_proving.key'});
    expect(plan.prepare, isFalse);
    expect(plan.show, isTrue);
  });

  test('a missing verifying key alone triggers its circuit', () {
    final plan = planWithout({'prepare_verifying.key'});
    expect(plan.prepare, isTrue);
    expect(plan.show, isFalse);
  });

  test('the setup decision ignores the verifying-key sidecar', () {
    final asked = <String>[];
    final plan = planKeySetup((name) {
      asked.add(name);
      return !name.endsWith('.digest');
    });
    expect(plan.any, isFalse);
    expect(asked.where((n) => n.endsWith('.digest')), isEmpty);
  });

  test('setup clears the sidecar with the keys it replaces', () async {
    final dir = Directory.systemTemp.createTempSync('keys_test');
    addTearDown(() => dir.deleteSync(recursive: true));
    final keys = Directory('${dir.path}/keys')..createSync();
    const prepare = [
      'prepare_proving.key',
      'prepare_verifying.key',
      'prepare_verifying.digest',
    ];
    const show = [
      'show_proving.key',
      'show_verifying.key',
      'show_verifying.digest'
    ];
    for (final n in [...prepare, ...show]) {
      File('${keys.path}/$n').writeAsStringSync('x');
    }
    File('${keys.path}/prepare_proving.key').deleteSync();

    // Setup deletes first, then reaches the Rust call, which cannot run here.
    await expectLater(
        RustFlowBackend(dir.path).ensureKeys(), throwsA(anything));

    for (final n in prepare) {
      expect(File('${keys.path}/$n').existsSync(), isFalse, reason: n);
    }
    for (final n in show) {
      expect(File('${keys.path}/$n').existsSync(), isTrue, reason: n);
    }
  });

  test('everything missing sets up both', () {
    final plan = planKeySetup((_) => false);
    expect(plan.prepare, isTrue);
    expect(plan.show, isTrue);
  });

  test('a failed load retries with setup only if setup has not just run', () {
    expect(retryLoadAfterSetup(setupRanThisCall: false), isTrue);
    expect(retryLoadAfterSetup(setupRanThisCall: true), isFalse);
  });

  test('UnavailableFlowBackend carries its reason into every error', () async {
    const backend = UnavailableFlowBackend('Missing asset x. Run it.');
    final calls = <Future<Object?> Function()>[
      backend.ensureKeys,
      backend.prepare,
    ];
    for (final call in calls) {
      await expectLater(
        call(),
        throwsA(predicate((e) => e.toString().contains('Missing asset x'))),
      );
    }
  });
}

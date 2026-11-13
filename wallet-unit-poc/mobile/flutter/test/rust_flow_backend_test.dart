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

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:openac/flow/flow_models.dart';

FlowBundle parse(String path) => FlowBundle.fromJson(
    jsonDecode(File(path).readAsStringSync()) as Map<String, dynamic>);

void main() {
  test('parses the sample bundle', () {
    final b = parse('test/fixtures/sample_bundle.json');
    expect(b.credential.issuer, 'https://issuer.example/');
    expect(b.credential.claims.map((c) => c.name), ['name', 'roc_birthday']);
    expect(b.credential.issuerKey.x, 'issuerX');
    expect(b.credential.deviceKey.y, 'deviceY');
    expect(b.requests.map((r) => r.id), ['A', 'B', 'C', 'D']);
    expect(b.request('A').showStatement, ['100', '200']);
    expect(b.scenarios.map((s) => s.expect), [
      ExpectedOutcome.accepted,
      ExpectedOutcome.policyFalse,
      ExpectedOutcome.rejected,
      ExpectedOutcome.rejected,
    ]);
  });

  test('ignores bundle keys the app does not read', () {
    final json = jsonDecode(
            File('test/fixtures/sample_bundle.json').readAsStringSync())
        as Map<String, dynamic>;
    json['sdkVersion'] = '5.0.0';
    json['circuit'] = {'size': '2k'};
    (json['credential'] as Map)['jwt'] = 'a.b.c';
    (json['requests'] as List).first['expectedExpressionResult'] = true;
    expect(FlowBundle.fromJson(json).requests, hasLength(4));
  });

  test('rejects an unknown schema version', () {
    final json =
        jsonDecode(File('test/fixtures/sample_bundle.json').readAsStringSync())
            as Map<String, dynamic>;
    json['schemaVersion'] = 2;
    expect(() => FlowBundle.fromJson(json), throwsFormatException);
  });

  test('rejects a scenario that points at a missing request', () {
    final json =
        jsonDecode(File('test/fixtures/sample_bundle.json').readAsStringSync())
            as Map<String, dynamic>;
    (json['scenarios'] as List).first['presentFor'] = 'Z';
    expect(() => FlowBundle.fromJson(json), throwsFormatException);
  });

  test('maps outcomes to verdicts', () {
    expect(Verdict.of(valid: true, expressionResult: true), Verdict.verified);
    expect(Verdict.of(valid: true, expressionResult: false),
        Verdict.policyNotSatisfied);
    expect(Verdict.of(valid: false, expressionResult: true), Verdict.rejected);
    expect(Verdict.of(valid: false, expressionResult: false), Verdict.rejected);
  });

  test('parses the generated bundle when present', () {
    const path = 'assets/flow/bundle.json';
    final b = parse(path);
    expect(b.scenarios, isNotEmpty);
    expect(b.requests, isNotEmpty);
  },
      skip: File('assets/flow/bundle.json').existsSync()
          ? false
          : 'assets/flow/bundle.json absent; run scripts/prepare-assets.sh');
}

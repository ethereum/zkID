import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mopro_flutter_bindings/mopro_flutter_bindings.dart';
import 'package:openac/main.dart';

void main() {
  testWidgets('offers only the complete benchmark', (t) async {
    await t.pumpWidget(
        MaterialApp(home: BenchmarkScreen(busy: ValueNotifier(false))));
    expect(find.text('Benchmark'), findsOneWidget);
    expect(find.text('Run Complete Benchmark'), findsOneWidget);
    expect(find.text('Run E2E Workflow'), findsNothing);
    expect(find.text('E2E Full Workflow'), findsNothing);
  });

  testWidgets('lists the key load and first verify rows', (t) async {
    await t.pumpWidget(MaterialApp(
      home: BenchmarkScreen(
        initialResults: BenchmarkResults(
          jwtSetupMs: BigInt.from(1),
          showSetupMs: BigInt.from(2),
          generateBlindsMs: BigInt.from(3),
          proveJwtMs: BigInt.from(4),
          reblindJwtMs: BigInt.from(5),
          proveShowMs: BigInt.from(6),
          reblindShowMs: BigInt.from(7),
          verifyJwtMs: BigInt.from(8),
          verifyShowMs: BigInt.from(9),
          jwtVkLoadMs: BigInt.from(1101),
          showVkLoadMs: BigInt.from(1102),
          verifyJwtFirstMs: BigInt.from(1103),
          verifyShowFirstMs: BigInt.from(1104),
          jwtProvingKeyBytes: BigInt.zero,
          jwtVerifyingKeyBytes: BigInt.zero,
          showProvingKeyBytes: BigInt.zero,
          showVerifyingKeyBytes: BigInt.zero,
          jwtProofBytes: BigInt.zero,
          showProofBytes: BigInt.zero,
          jwtWitnessBytes: BigInt.zero,
          showWitnessBytes: BigInt.zero,
        ),
      ),
    ));
    for (final row in {
      'Load Prepare VK': '1101',
      'Load Show VK': '1102',
      'Verify Prepare (first)': '1103',
      'Verify Show (first)': '1104',
    }.entries) {
      await t.scrollUntilVisible(find.text(row.key), 100);
      expect(find.text(row.key), findsOneWidget);
      expect(find.text(row.value), findsOneWidget);
    }
    expect(find.text('Verify Prepare'), findsOneWidget);
    expect(find.text('Verify Show'), findsOneWidget);
  });
}

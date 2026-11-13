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

  testWidgets('each timing label sits on the row of its own value', (t) async {
    BigInt ms(int v) => BigInt.from(v);
    await t.pumpWidget(MaterialApp(
      home: BenchmarkScreen(
        runBenchmark: () async => BenchmarkResults(
          jwtSetupMs: ms(101),
          showSetupMs: ms(102),
          generateBlindsMs: ms(103),
          proveJwtMs: ms(104),
          reblindJwtMs: ms(105),
          proveShowMs: ms(106),
          reblindShowMs: ms(107),
          verifyJwtMs: ms(108),
          verifyShowMs: ms(109),
          jwtVkLoadMs: ms(110),
          showVkLoadMs: ms(111),
          verifyJwtFirstMs: ms(112),
          verifyShowFirstMs: ms(113),
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
    await t.tap(find.text('Run Complete Benchmark'));
    await t.pumpAndSettle();
    for (final row in {
      'Verify Prepare': '108',
      'Verify Show': '109',
      'Load Prepare VK': '110',
      'Load Show VK': '111',
      'Verify Prepare (first)': '112',
      'Verify Show (first)': '113',
    }.entries) {
      await t.scrollUntilVisible(find.text(row.key), 100);
      expect(find.text(row.key), findsOneWidget);
      expect(find.text(row.value), findsOneWidget);
      expect(
        (t.getCenter(find.text(row.key)).dy -
                t.getCenter(find.text(row.value)).dy)
            .abs(),
        lessThan(1),
        reason: '${row.key} is not on the row showing ${row.value}',
      );
    }
  });
}

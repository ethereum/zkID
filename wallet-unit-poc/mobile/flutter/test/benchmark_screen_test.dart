import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
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
}

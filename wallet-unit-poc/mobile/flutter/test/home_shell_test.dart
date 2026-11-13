import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:openac/flow/flow_models.dart';
import 'package:openac/flow/flow_screen.dart';
import 'package:openac/home_shell.dart';

import 'fake_flow_backend.dart';

Future<FlowBundle> sampleBundle() async => FlowBundle.fromJson(
    jsonDecode(File('test/fixtures/sample_bundle.json').readAsStringSync())
        as Map<String, dynamic>);

Widget shell(FakeFlowBackend backend, {String? assetsError}) => MaterialApp(
      home: HomeShell(
        backend: backend,
        loadBundle: sampleBundle,
        assetsError: assetsError,
        benchmarkBuilder: (busy) => const Center(child: Text('bench screen')),
      ),
    );

void main() {
  testWidgets('starts on Flow with both destinations', (t) async {
    await t.pumpWidget(shell(FakeFlowBackend()));
    await t.pumpAndSettle();
    expect(find.byType(NavigationBar), findsOneWidget);
    expect(find.byType(FlowScreen), findsOneWidget);
    expect(find.text('Benchmark'), findsOneWidget);
  });

  testWidgets('switching away from Flow disposes it and unloads', (t) async {
    final backend = FakeFlowBackend();
    await t.pumpWidget(shell(backend));
    await t.pumpAndSettle();
    expect(backend.unloadCount, 0);

    await t.tap(find.text('Benchmark'));
    await t.pumpAndSettle();
    expect(find.byType(FlowScreen), findsNothing);
    expect(find.text('bench screen'), findsOneWidget);
    expect(backend.unloadCount, 1);

    await t.tap(find.text('Flow'));
    await t.pumpAndSettle();
    expect(find.byType(FlowScreen), findsOneWidget);
    // A fresh flow starts over from the keys step.
    expect(find.text('Set up and load'), findsOneWidget);
  });

  testWidgets('the bar is locked while the flow runs a backend call',
      (t) async {
    final backend = FakeFlowBackend()..gate = Completer<void>();
    await t.pumpWidget(shell(backend));
    await t.pumpAndSettle();

    await t.tap(find.widgetWithText(FilledButton, 'Set up and load'));
    await t.pump();
    await t.tap(find.text('Benchmark'), warnIfMissed: false);
    await t.pump();
    expect(find.byType(FlowScreen), findsOneWidget);
    expect(backend.unloadCount, 0);

    backend.gate!.complete();
    await t.pumpAndSettle();
    await t.tap(find.text('Benchmark'));
    await t.pumpAndSettle();
    expect(find.text('bench screen'), findsOneWidget);
  });

  testWidgets('busy stays true until the flow unload completes', (t) async {
    final backend = FakeFlowBackend()..unloadGate = Completer<void>();
    ValueNotifier<bool>? busy;
    await t.pumpWidget(MaterialApp(
      home: HomeShell(
        backend: backend,
        loadBundle: sampleBundle,
        benchmarkBuilder: (b) {
          busy = b;
          return const Center(child: Text('bench screen'));
        },
      ),
    ));
    await t.pumpAndSettle();

    await t.tap(find.text('Benchmark'));
    await t.pump();
    await t.pump();
    expect(backend.unloadCount, 1);
    expect(busy!.value, isTrue);

    backend.unloadGate!.complete();
    await t.pumpAndSettle();
    expect(busy!.value, isFalse);
  });

  testWidgets('shows a startup asset error', (t) async {
    await t
        .pumpWidget(shell(FakeFlowBackend(), assetsError: 'Missing asset x'));
    await t.pumpAndSettle();
    expect(find.text('Missing asset x'), findsOneWidget);
  });
}

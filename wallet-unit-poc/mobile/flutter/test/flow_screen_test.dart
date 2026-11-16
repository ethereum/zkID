import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:openac/flow/flow_backend.dart';
import 'package:openac/flow/flow_models.dart';
import 'package:openac/flow/flow_screen.dart';

import 'fake_flow_backend.dart';

Future<FlowBundle> sampleBundle() async => FlowBundle.fromJson(
    jsonDecode(File('test/fixtures/sample_bundle.json').readAsStringSync())
        as Map<String, dynamic>);

Future<void> pumpFlow(WidgetTester t, FakeFlowBackend backend,
    {ValueNotifier<bool>? busy}) async {
  t.view.physicalSize = const Size(800, 4000);
  t.view.devicePixelRatio = 1;
  addTearDown(t.view.reset);
  await t.pumpWidget(MaterialApp(
    home: FlowScreen(backend: backend, loadBundle: sampleBundle, busy: busy),
  ));
  await t.pumpAndSettle();
}

Future<void> tapButton(WidgetTester t, String label) async {
  await t.tap(find.widgetWithText(FilledButton, label));
  await t.pumpAndSettle();
}

Future<void> openDetails(WidgetTester t, String cardTitle) async {
  final details = find.descendant(
    of: find.widgetWithText(Card, cardTitle),
    matching: find.text('Details'),
  );
  await t.tap(details);
  await t.pumpAndSettle();
}

bool enabled(WidgetTester t, String label) =>
    t
        .widget<FilledButton>(find.widgetWithText(FilledButton, label))
        .onPressed !=
    null;

void main() {
  testWidgets('happy path renders each step and the verdict', (t) async {
    final backend = FakeFlowBackend();
    await pumpFlow(t, backend);

    expect(enabled(t, 'Set up and load'), isTrue);
    expect(enabled(t, 'Prepare'), isFalse);

    await tapButton(t, 'Set up and load');
    expect(find.text('Keys ready in 1.5 s'), findsOneWidget);
    expect(find.textContaining('Alice'), findsOneWidget);
    expect(find.textContaining('https://issuer.example/'), findsOneWidget);

    await tapButton(t, 'Prepare');
    expect(find.text('Prepared in 5.4 s'), findsOneWidget);
    await openDetails(t, 'Prepare once');
    expect(find.text('Prove: 5000 ms'), findsOneWidget);
    expect(find.text('Fingerprint aaaaaaaaaaaaaaaa'), findsOneWidget);
    expect(find.textContaining('none of the claim values'), findsOneWidget);
    expect(find.textContaining('Corner bar'), findsNothing);

    await tapButton(t, 'Present');
    expect(find.text('Presented in 1.0 s'), findsOneWidget);
    await openDetails(t, 'Present a proof');
    expect(find.textContaining('show0000000000001'), findsOneWidget);

    await tapButton(t, 'Verify');
    expect(find.text('VERIFIED'), findsOneWidget);
    expect(find.text('Verified in 30 ms'), findsOneWidget);
    expect(find.text('Matches the expected outcome.'), findsOneWidget);
  });

  testWidgets('details are collapsed by default; results stay visible',
      (t) async {
    await pumpFlow(t, FakeFlowBackend());
    await tapButton(t, 'Set up and load');
    await tapButton(t, 'Prepare');
    await tapButton(t, 'Present');
    await tapButton(t, 'Verify');

    expect(find.text('Prepared in 5.4 s'), findsOneWidget);
    expect(find.text('VERIFIED'), findsOneWidget);
    expect(find.text('Fingerprint aaaaaaaaaaaaaaaa'), findsNothing);
    expect(find.text('Issuer trusted'), findsNothing);

    await openDetails(t, 'Prepare once');
    expect(find.text('Fingerprint aaaaaaaaaaaaaaaa'), findsOneWidget);
    await openDetails(t, 'Verify');
    expect(find.text('Issuer trusted'), findsOneWidget);
  });

  testWidgets('details show instance size, commitments and the issuer key',
      (t) async {
    await pumpFlow(t, FakeFlowBackend());
    await tapButton(t, 'Set up and load');
    await tapButton(t, 'Prepare');
    await tapButton(t, 'Present');
    await tapButton(t, 'Verify');

    await openDetails(t, 'Prepare once');
    expect(find.text('Proof: 120.6 KB + instance 0.8 KB'), findsOneWidget);
    expect(find.text('Commitment c0ffee'), findsOneWidget);
    await openDetails(t, 'Present a proof');
    expect(find.text('Commitment (Prepare) cw0001'), findsOneWidget);
    expect(find.text('Commitment (Show) cw0001'), findsOneWidget);
    await openDetails(t, 'Verify');
    expect(find.textContaining('x=111111…111111'), findsOneWidget);
  });

  testWidgets('credential has no button and Prepare is enabled after keys',
      (t) async {
    await pumpFlow(t, FakeFlowBackend());
    await tapButton(t, 'Set up and load');

    final card = find.widgetWithText(Card, 'Your credential');
    expect(find.descendant(of: card, matching: find.byType(FilledButton)),
        findsNothing);
    expect(enabled(t, 'Prepare'), isTrue);
  });

  testWidgets('a rejected scenario shows the reason and still matches',
      (t) async {
    final backend = FakeFlowBackend();
    await pumpFlow(t, backend);
    await tapButton(t, 'Set up and load');
    await tapButton(t, 'Prepare');
    await t.tap(find.text('Replayed proof'));
    await t.pumpAndSettle();
    await tapButton(t, 'Present');
    await tapButton(t, 'Verify');
    expect(find.text('REJECTED'), findsOneWidget);
    expect(find.text('nonce mismatch'), findsOneWidget);
    expect(find.text('Matches the expected outcome.'), findsOneWidget);
  });

  testWidgets('present again shows old and new fingerprints', (t) async {
    final backend = FakeFlowBackend();
    await pumpFlow(t, backend);
    await tapButton(t, 'Set up and load');
    await tapButton(t, 'Prepare');
    await tapButton(t, 'Present');
    await tapButton(t, 'Present again');
    await openDetails(t, 'Present a proof');

    expect(find.text('Show show0000000000001'), findsOneWidget);
    expect(find.text('Show show0000000000002'), findsOneWidget);
    expect(find.text('Previous'), findsOneWidget);
  });

  testWidgets('an error shows the message and the retry button works',
      (t) async {
    final backend = FakeFlowBackend()..failNext = 'ensureKeys';
    await pumpFlow(t, backend);
    await tapButton(t, 'Set up and load');
    expect(find.textContaining('ensureKeys failed'), findsOneWidget);
    expect(enabled(t, 'Set up and load'), isTrue);

    await tapButton(t, 'Set up and load');
    expect(find.textContaining('ensureKeys failed'), findsNothing);
    expect(find.text('Keys ready in 1.5 s'), findsOneWidget);
  });

  testWidgets('every action button is disabled while a call runs', (t) async {
    final backend = FakeFlowBackend();
    await pumpFlow(t, backend);
    await tapButton(t, 'Set up and load');
    await tapButton(t, 'Prepare');

    backend.gate = Completer<void>();
    await t.tap(find.widgetWithText(FilledButton, 'Present'));
    await t.pump();
    for (final label in [
      'Set up and load',
      'Prepare',
      'Present',
      'Verify',
    ]) {
      expect(enabled(t, label), isFalse, reason: label);
    }
    final chip =
        t.widget<ChoiceChip>(find.widgetWithText(ChoiceChip, 'Over 18'));
    expect(chip.onSelected, isNull);

    backend.gate!.complete();
    await t.pumpAndSettle();
    expect(enabled(t, 'Verify'), isTrue);
  });

  testWidgets('a missing bundle shows the loader error', (t) async {
    await t.pumpWidget(MaterialApp(
      home: FlowScreen(
        backend: FakeFlowBackend(),
        loadBundle: () async =>
            throw StateError('Run scripts/prepare-assets.sh'),
      ),
    ));
    await t.pumpAndSettle();
    expect(find.textContaining('prepare-assets.sh'), findsOneWidget);
  });

  testWidgets('the whole flow fits 360x740 at 1.3x text without overflow',
      (t) async {
    t.view.physicalSize = const Size(360, 740);
    t.view.devicePixelRatio = 1;
    addTearDown(t.view.reset);
    await t.pumpWidget(MaterialApp(
      builder: (context, child) => MediaQuery(
        data: MediaQuery.of(context).copyWith(
          textScaler: const TextScaler.linear(1.3),
        ),
        child: child!,
      ),
      home: FlowScreen(backend: FakeFlowBackend(), loadBundle: sampleBundle),
    ));
    await t.pumpAndSettle();

    Future<void> tapScrolled(String label) async {
      final button = find.widgetWithText(FilledButton, label);
      await t.scrollUntilVisible(button, 200);
      await t.ensureVisible(button);
      await t.pumpAndSettle();
      await t.tap(button);
      await t.pumpAndSettle();
    }

    await tapScrolled('Set up and load');
    await tapScrolled('Prepare');
    await tapScrolled('Present');
    await tapScrolled('Present again');
    await tapScrolled('Verify');
    await t.scrollUntilVisible(find.text('VERIFIED'), 200);
    expect(find.text('VERIFIED'), findsOneWidget);
    expect(t.takeException(), isNull);
  });

  testWidgets('a verdict that contradicts the scenario is flagged', (t) async {
    await pumpFlow(t, _ContradictingBackend());
    await tapButton(t, 'Set up and load');
    await tapButton(t, 'Prepare');
    await tapButton(t, 'Present');
    await tapButton(t, 'Verify');

    // Scenario "Over 18" expects VERIFIED; the backend rejects.
    expect(find.text('REJECTED'), findsOneWidget);
    expect(find.text('Matches the expected outcome.'), findsNothing);
    expect(
      find.text('Does not match the expected outcome (VERIFIED).'),
      findsOneWidget,
    );
  });
}

class _ContradictingBackend extends FakeFlowBackend {
  @override
  Future<VerifyOutcome> verify(Presentation p, FlowRequest against) async {
    final ok = await super.verify(p, against);
    return VerifyOutcome(
      valid: false,
      expressionResult: ok.expressionResult,
      proofsLinked: ok.proofsLinked,
      issuerTrusted: false,
      normalizationMatches: ok.normalizationMatches,
      nonceMatches: ok.nonceMatches,
      policyMatches: ok.policyMatches,
      issuerKeyX: ok.issuerKeyX,
      issuerKeyY: ok.issuerKeyY,
      vkLoadMs: ok.vkLoadMs,
      verifyMs: ok.verifyMs,
      failure: 'issuer not trusted',
    );
  }
}

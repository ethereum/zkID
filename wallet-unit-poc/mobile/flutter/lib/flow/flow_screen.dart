import 'package:flutter/material.dart';

import 'flow_backend.dart';
import 'flow_controller.dart';
import 'flow_models.dart';

class FlowScreen extends StatefulWidget {
  const FlowScreen({
    super.key,
    required this.backend,
    required this.loadBundle,
    this.busy,
  });

  final FlowBackend backend;
  final Future<FlowBundle> Function() loadBundle;
  final ValueNotifier<bool>? busy;

  @override
  State<FlowScreen> createState() => _FlowScreenState();
}

class _FlowScreenState extends State<FlowScreen> {
  late final FlowController _c = FlowController(
    backend: widget.backend,
    loadBundle: widget.loadBundle,
    sharedBusy: widget.busy,
  )..load();

  @override
  void dispose() {
    _c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('OpenAC credential flow')),
      body: ListenableBuilder(
        listenable: _c,
        builder: (context, _) {
          if (_c.bundleError != null) {
            return _Message(
                icon: Icons.error_outline, text: _c.bundleError!, error: true);
          }
          if (_c.bundle == null) {
            return const Center(child: CircularProgressIndicator());
          }
          return ListView(
            padding: const EdgeInsets.all(16),
            children: [
              _keysStep(),
              _credentialStep(),
              _prepareStep(),
              _requestStep(),
              _presentStep(),
              _verifyStep(),
            ],
          );
        },
      ),
    );
  }

  Widget _keysStep() {
    final k = _c.keys;
    return _StepCard(
      number: 1,
      title: 'Set up keys',
      status: _c.status(FlowStep.keys),
      error: _c.error(FlowStep.keys),
      actionLabel: 'Set up and load',
      onAction: _c.canRun(FlowStep.keys) ? _c.runKeys : null,
      timing: k == null
          ? null
          : k.setupRan
              ? 'Keys ready in ${_duration(k.setupMs + k.loadMs)}'
              : 'Keys loaded in ${_duration(k.loadMs)}',
      details: [
        const Text(
            'One-time proving keys for the two circuits. Setup is slow; later runs only load them.'),
        if (k != null)
          _Lines([
            k.setupRan
                ? 'Setup ran: ${k.setupMs} ms'
                : 'Keys already existed, setup skipped',
            'Load: ${k.loadMs} ms',
          ]),
      ],
    );
  }

  Widget _credentialStep() {
    final cred = _c.bundle!.credential;
    final shown = _c.status(FlowStep.credential) != StepStatus.disabled;
    return _StepCard(
      number: 2,
      title: 'Your credential',
      status: _c.status(FlowStep.credential),
      result: !shown
          ? null
          : Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                for (final claim in cred.claims)
                  _KeyValue(claim.name, claim.value),
                _KeyValue('Issuer', cred.issuer),
              ],
            ),
      details: [
        const Text(
            'What we would normally hand over to a verifier. Next, we prove things about it instead.'),
        if (shown) ...[
          _KeyValue('Issuer key', _jwk(cred.issuerKey)),
          _KeyValue('Device key', _jwk(cred.deviceKey)),
        ],
      ],
    );
  }

  Widget _prepareStep() {
    final p = _c.prepared;
    return _StepCard(
      number: 3,
      title: 'Prepare once',
      status: _c.status(FlowStep.prepare),
      error: _c.error(FlowStep.prepare),
      actionLabel: 'Prepare',
      onAction: _c.canRun(FlowStep.prepare) ? _c.runPrepare : null,
      timing:
          p == null ? null : 'Prepared in ${_duration(p.witnessMs + p.proveMs)}',
      details: [
        const Text(
            'Proves the issuer signed this credential. Done once; reused for every verifier.'),
        if (p != null) ...[
          _Lines([
            'Witness: ${p.witnessMs} ms',
            'Prove: ${p.proveMs} ms',
            'Proof: ${_kb(p.proofBytes)}',
          ]),
          _Mono('Fingerprint ${p.proofFingerprint}'),
          const Text('The proof holds none of the claim values above.'),
        ],
      ],
    );
  }

  Widget _requestStep() {
    final enabled = _c.status(FlowStep.request) != StepStatus.disabled;
    final s = _c.scenario;
    final req = _c.presentRequest;
    return _StepCard(
      number: 4,
      title: 'A verifier asks',
      status: _c.status(FlowStep.request),
      result: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              for (final sc in _c.bundle!.scenarios)
                ChoiceChip(
                  label: Text(sc.title),
                  selected: sc.id == s.id,
                  onSelected: enabled && !_c.busy
                      ? (_) => _c.selectScenario(sc.id)
                      : null,
                ),
            ],
          ),
          const SizedBox(height: 8),
          Text(s.description),
        ],
      ),
      details: [
        const Text('Pick a scenario. Each one is a different kind of request.'),
        if (enabled) ...[
          _KeyValue('Verifier', req.verifier),
          _KeyValue('Asks', req.policyText),
          _KeyValue('Nonce', req.nonce, mono: true),
        ],
      ],
    );
  }

  Widget _presentStep() {
    final p = _c.presentation;
    final prev = _c.previousPresentation;
    return _StepCard(
      number: 5,
      title: 'Present a proof',
      status: _c.status(FlowStep.present),
      error: _c.error(FlowStep.present),
      actionLabel: p == null ? 'Present' : 'Present again',
      onAction: _c.canRun(FlowStep.present) ? _c.runPresent : null,
      timing: p == null ? null : 'Presented in ${_duration(p.totalMs)}',
      details: [
        const Text(
            'Proves the policy for this verifier and re-randomises both proofs, so they cannot be matched to earlier ones.'),
        if (p != null) ...[
          _Lines([
            'Show prove: ${p.showProveMs} ms',
            'Reblind: ${p.prepareReblindMs} + ${p.showReblindMs} ms',
            'Sizes: ${_kb(p.prepareProof.length)} + ${_kb(p.showProof.length)}',
          ]),
          _fingerprints(prev == null ? 'This presentation' : 'New', p),
          if (prev != null) ...[
            _fingerprints('Previous', prev),
            const Text('Same credential, but nothing in the two proofs matches.'),
          ],
        ],
      ],
    );
  }

  Widget _fingerprints(String label, Presentation p) => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label, style: const TextStyle(fontWeight: FontWeight.w600)),
          _Mono('Prepare ${p.prepareFingerprint}'),
          _Mono('Show ${p.showFingerprint}'),
          _Mono('Commitment ${p.prepareCommWShared}'),
        ],
      );

  Widget _verifyStep() {
    final v = _c.verifyOutcome;
    final against = _c.verifyRequest;
    return _StepCard(
      number: 6,
      title: 'Verify',
      status: _c.status(FlowStep.verify),
      error: _c.error(FlowStep.verify),
      actionLabel: 'Verify',
      onAction: _c.canRun(FlowStep.verify) ? _c.runVerify : null,
      result: v == null
          ? null
          : _VerdictBanner(
              verdict: _c.verdict!,
              matches: _c.matchesExpected!,
              expected: _c.scenario.expect.verdict,
              failure: v.failure,
            ),
      timing: v == null ? null : 'Verified in ${_duration(v.vkLoadMs + v.verifyMs)}',
      details: [
        const Text('The verifier checks the proofs against what it asked for.'),
        if (v != null) ...[
          _Check('Proofs linked to one credential', v.proofsLinked),
          _Check('Issuer trusted', v.issuerTrusted),
          _Check('Claims normalized as expected', v.normalizationMatches),
          _Check('Nonce is ${against.verifier}\'s', v.nonceMatches),
          _Check('Policy is what was asked', v.policyMatches),
          Text('Verify: ${v.verifyMs} ms, key load: ${v.vkLoadMs} ms'),
        ],
      ],
    );
  }
}

String _jwk(PublicJwk k) => '${k.crv} x=${_short(k.x)} y=${_short(k.y)}';

String _short(String s) =>
    s.length <= 14 ? s : '${s.substring(0, 6)}…${s.substring(s.length - 6)}';

String _duration(int ms) =>
    ms < 1000 ? '$ms ms' : '${(ms / 1000).toStringAsFixed(1)} s';

String _kb(int bytes) => '${(bytes / 1024).toStringAsFixed(1)} KB';

class _StepCard extends StatelessWidget {
  const _StepCard({
    required this.number,
    required this.title,
    required this.status,
    this.error,
    this.actionLabel,
    this.onAction,
    this.result,
    this.timing,
    this.details = const [],
  });

  final int number;
  final String title;
  final StepStatus status;
  final String? error;
  final String? actionLabel;
  final VoidCallback? onAction;
  final Widget? result;
  final String? timing;

  /// Shown in a collapsed "Details" tile.
  final List<Widget> details;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    final disabled = status == StepStatus.disabled;
    return Opacity(
      opacity: disabled ? 0.5 : 1,
      child: Card(
        margin: const EdgeInsets.only(bottom: 12),
        child: Padding(
          padding: const EdgeInsets.fromLTRB(16, 16, 16, 4),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Wraps so the button drops below the title on narrow screens
              // or large text scales.
              SizedBox(
                width: double.infinity,
                child: Wrap(
                  alignment: WrapAlignment.spaceBetween,
                  crossAxisAlignment: WrapCrossAlignment.center,
                  runSpacing: 8,
                  children: [
                    Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        _StatusDot(number: number, status: status),
                        const SizedBox(width: 12),
                        Flexible(
                          child: Text(title,
                              style: theme.textTheme.titleMedium
                                  ?.copyWith(fontWeight: FontWeight.w600)),
                        ),
                      ],
                    ),
                    if (actionLabel != null)
                      FilledButton(
                          onPressed: onAction, child: Text(actionLabel!)),
                  ],
                ),
              ),
              if (result != null && !disabled) ...[
                const SizedBox(height: 12),
                result!,
              ],
              if (timing != null && !disabled) ...[
                const SizedBox(height: 8),
                Text(timing!,
                    style: theme.textTheme.bodyMedium?.copyWith(
                        color: scheme.onSurface, fontWeight: FontWeight.w600)),
              ],
              if (error != null) ...[
                const SizedBox(height: 8),
                Text(error!, style: TextStyle(color: scheme.error)),
              ],
              ExpansionTile(
                title: Text('Details',
                    style: theme.textTheme.labelLarge
                        ?.copyWith(color: scheme.onSurfaceVariant)),
                dense: true,
                visualDensity: VisualDensity.compact,
                minTileHeight: 32,
                tilePadding: EdgeInsets.zero,
                childrenPadding: const EdgeInsets.only(bottom: 8),
                expandedCrossAxisAlignment: CrossAxisAlignment.start,
                shape: const Border(),
                collapsedShape: const Border(),
                children: [
                  for (final d in details)
                    Padding(
                      padding: const EdgeInsets.only(bottom: 8),
                      child: d,
                    ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _StatusDot extends StatelessWidget {
  const _StatusDot({required this.number, required this.status});

  final int number;
  final StepStatus status;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return switch (status) {
      StepStatus.running => const SizedBox(
          width: 28,
          height: 28,
          child: CircularProgressIndicator(strokeWidth: 3)),
      StepStatus.done => const Icon(Icons.check_circle, color: Colors.green),
      StepStatus.error => Icon(Icons.error, color: scheme.error),
      _ => CircleAvatar(
          radius: 14,
          backgroundColor: status == StepStatus.active
              ? scheme.primary
              : scheme.surfaceContainerHighest,
          foregroundColor: status == StepStatus.active
              ? scheme.onPrimary
              : scheme.onSurfaceVariant,
          child: Text('$number'),
        ),
    };
  }
}

class _Lines extends StatelessWidget {
  const _Lines(this.lines);

  final List<String> lines;

  @override
  Widget build(BuildContext context) => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [for (final l in lines) Text(l)],
      );
}

class _Mono extends StatelessWidget {
  const _Mono(this.text);

  final String text;

  @override
  Widget build(BuildContext context) =>
      Text(text, style: const TextStyle(fontFamily: 'monospace', fontSize: 13));
}

class _KeyValue extends StatelessWidget {
  const _KeyValue(this.label, this.value, {this.mono = false});

  final String label;
  final String value;
  final bool mono;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 2),
        child: Text.rich(TextSpan(children: [
          TextSpan(
              text: '$label: ',
              style: const TextStyle(fontWeight: FontWeight.w600)),
          TextSpan(
              text: value,
              style: mono
                  ? const TextStyle(fontFamily: 'monospace', fontSize: 13)
                  : null),
        ])),
      );
}

class _Check extends StatelessWidget {
  const _Check(this.label, this.ok);

  final String label;
  final bool ok;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 2),
        child: Row(
          children: [
            Icon(ok ? Icons.check : Icons.close,
                size: 18,
                color: ok ? Colors.green : Theme.of(context).colorScheme.error),
            const SizedBox(width: 8),
            Expanded(child: Text(label)),
          ],
        ),
      );
}

class _VerdictBanner extends StatelessWidget {
  const _VerdictBanner({
    required this.verdict,
    required this.matches,
    required this.expected,
    this.failure,
  });

  final Verdict verdict;
  final bool matches;
  final Verdict expected;
  final String? failure;

  @override
  Widget build(BuildContext context) {
    final textTheme = Theme.of(context).textTheme;
    final (bg, fg) = switch (verdict) {
      Verdict.verified => (Colors.green.shade100, Colors.green.shade900),
      Verdict.policyNotSatisfied => (
          Colors.orange.shade100,
          Colors.orange.shade900
        ),
      Verdict.rejected => (Colors.red.shade100, Colors.red.shade900),
    };
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      decoration:
          BoxDecoration(color: bg, borderRadius: BorderRadius.circular(8)),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(verdict.label,
              style: textTheme.titleMedium
                  ?.copyWith(color: fg, fontWeight: FontWeight.w600)),
          if (failure != null) Text(failure!, style: TextStyle(color: fg)),
          Text(
              matches
                  ? 'Matches the expected outcome.'
                  : 'Does not match the expected outcome (${expected.label}).',
              style: TextStyle(color: fg)),
        ],
      ),
    );
  }
}

class _Message extends StatelessWidget {
  const _Message({required this.icon, required this.text, this.error = false});

  final IconData icon;
  final String text;
  final bool error;

  @override
  Widget build(BuildContext context) => Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(icon,
                  size: 40,
                  color: error ? Theme.of(context).colorScheme.error : null),
              const SizedBox(height: 12),
              Text(text, textAlign: TextAlign.center),
            ],
          ),
        ),
      );
}

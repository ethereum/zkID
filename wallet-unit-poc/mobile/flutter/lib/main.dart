import 'package:flutter/material.dart';

import 'package:openac/assets.dart';
import 'package:openac/flow/flow_backend.dart';
import 'package:openac/flow/rust_flow_backend.dart';
import 'package:openac/home_shell.dart';

import 'package:mopro_flutter_bindings/mopro_flutter_bindings.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();
  String? assetsError;
  String? docsPath;
  try {
    docsPath = await prepareAssets();
  } catch (e) {
    assetsError = e.toString();
  }
  runApp(MyApp(docsPath: docsPath, assetsError: assetsError));
}

class MyApp extends StatelessWidget {
  const MyApp({super.key, this.docsPath, this.assetsError});

  /// Null when asset preparation failed; the flow then reports the error.
  final String? docsPath;
  final String? assetsError;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      theme: ThemeData(primarySwatch: Colors.blue, useMaterial3: true),
      home: HomeShell(
        backend: docsPath == null
            ? UnavailableFlowBackend(
                assetsError ?? 'Circuit assets are not available.')
            : RustFlowBackend(docsPath!),
        assetsError: assetsError,
        benchmarkBuilder: (busy) => BenchmarkScreen(busy: busy),
      ),
    );
  }
}

class BenchmarkScreen extends StatefulWidget {
  const BenchmarkScreen({super.key, this.busy, this.initialResults});

  /// Set while a Rust call runs, so the shell can lock its navigation.
  final ValueNotifier<bool>? busy;

  @visibleForTesting
  final BenchmarkResults? initialResults;

  @override
  State<BenchmarkScreen> createState() => _BenchmarkScreenState();
}

class _BenchmarkScreenState extends State<BenchmarkScreen> {
  bool _operating = false;
  bool get _isOperating => _operating;
  set _isOperating(bool v) {
    _operating = v;
    widget.busy?.value = v;
  }

  Exception? _error;

  late BenchmarkResults? _benchmarkResults = widget.initialResults;

  Future<void> _runBenchmark() async {
    setState(() {
      _isOperating = true;
      _error = null;
      _benchmarkResults = null;
    });
    try {
      final docs = await getDocumentsPath();
      final results = await runCompleteBenchmark(
        documentsPath: docs,
      );
      setState(() {
        _benchmarkResults = results;
        _isOperating = false;
      });
    } catch (e) {
      setState(() {
        _error = Exception('Benchmark failed: $e');
        _isOperating = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;
    return Scaffold(
      appBar: AppBar(
        title: const Text('Benchmark'),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            if (_error != null) ...[
              Card(
                margin: EdgeInsets.zero,
                color: scheme.errorContainer,
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Row(
                    children: [
                      Icon(Icons.error, color: scheme.error),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          _error.toString(),
                          style: TextStyle(color: scheme.onErrorContainer),
                        ),
                      ),
                      IconButton(
                        icon: const Icon(Icons.close),
                        onPressed: () => setState(() => _error = null),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),
            ],

            // ── Complete Benchmark ─────────────────────────────────────────
            Card(
              elevation: 4,
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Icon(Icons.speed, color: scheme.primary),
                        const SizedBox(width: 8),
                        Text(
                          'Complete Benchmark',
                          style: theme.textTheme.titleMedium
                              ?.copyWith(fontWeight: FontWeight.w600),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    Text(
                      'Runs all 9 operations and reports timing + artifact sizes.',
                      style: theme.textTheme.bodySmall
                          ?.copyWith(color: scheme.onSurfaceVariant),
                    ),
                    const SizedBox(height: 12),
                    SizedBox(
                      width: double.infinity,
                      child: ElevatedButton.icon(
                        onPressed: _isOperating ? null : _runBenchmark,
                        style: ElevatedButton.styleFrom(
                          backgroundColor: scheme.primary,
                          foregroundColor: scheme.onPrimary,
                          padding: const EdgeInsets.all(16),
                        ),
                        icon: _isOperating
                            ? SizedBox(
                                width: 20,
                                height: 20,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                  color: scheme.onPrimary,
                                ),
                              )
                            : const Icon(Icons.speed),
                        label: Text(_isOperating
                            ? 'Running Benchmark...'
                            : 'Run Complete Benchmark'),
                      ),
                    ),
                  ],
                ),
              ),
            ),

            if (_benchmarkResults != null) ...[
              const SizedBox(height: 16),
              _buildBenchmarkResults(),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildBenchmarkResults() {
    if (_benchmarkResults == null) return const SizedBox.shrink();
    final r = _benchmarkResults!;
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;

    return Card(
      elevation: 4,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Row(
                  children: [
                    Icon(Icons.assessment, color: scheme.primary),
                    const SizedBox(width: 8),
                    Text('Benchmark Results',
                        style: theme.textTheme.titleMedium
                            ?.copyWith(fontWeight: FontWeight.w600)),
                  ],
                ),
                IconButton(
                  icon: const Icon(Icons.close, size: 20),
                  onPressed: () => setState(() => _benchmarkResults = null),
                  tooltip: 'Clear results',
                ),
              ],
            ),
            const SizedBox(height: 16),
            Text('Timing Metrics',
                style: theme.textTheme.titleSmall?.copyWith(
                    fontWeight: FontWeight.w600, color: scheme.primary)),
            const SizedBox(height: 8),
            Table(
              border: TableBorder.all(color: scheme.outlineVariant),
              columnWidths: const {
                0: FlexColumnWidth(2),
                1: FlexColumnWidth(1),
              },
              children: [
                _tableHeader(['Operation', 'Time (ms)']),
                _timingRow('Prepare Setup', r.jwtSetupMs),
                _timingRow('Show Setup', r.showSetupMs),
                _timingRow('Generate Blinds', r.generateBlindsMs),
                _timingRow('Prove Prepare', r.proveJwtMs),
                _timingRow('Reblind Prepare', r.reblindJwtMs),
                _timingRow('Prove Show', r.proveShowMs),
                _timingRow('Reblind Show', r.reblindShowMs),
                _timingRow('Verify Prepare', r.verifyJwtMs),
                _timingRow('Verify Show', r.verifyShowMs),
                _timingRow('Load Prepare VK', r.jwtVkLoadMs),
                _timingRow('Load Show VK', r.showVkLoadMs),
                _timingRow('Verify Prepare (first)', r.verifyJwtFirstMs),
                _timingRow('Verify Show (first)', r.verifyShowFirstMs),
              ],
            ),
            const SizedBox(height: 24),
            Text('Artifact Sizes',
                style: theme.textTheme.titleSmall?.copyWith(
                    fontWeight: FontWeight.w600, color: scheme.primary)),
            const SizedBox(height: 8),
            Table(
              border: TableBorder.all(color: scheme.outlineVariant),
              columnWidths: const {
                0: FlexColumnWidth(2),
                1: FlexColumnWidth(1),
              },
              children: [
                _tableHeader(['Artifact', 'Size']),
                _sizeRow('Prepare Proving Key', r.jwtProvingKeyBytes),
                _sizeRow('Prepare Verifying Key', r.jwtVerifyingKeyBytes),
                _sizeRow('Show Proving Key', r.showProvingKeyBytes),
                _sizeRow('Show Verifying Key', r.showVerifyingKeyBytes),
                _sizeRow('Prepare Proof', r.jwtProofBytes),
                _sizeRow('Show Proof', r.showProofBytes),
                _sizeRow('Prepare Witness', r.jwtWitnessBytes),
                _sizeRow('Show Witness', r.showWitnessBytes),
              ],
            ),
          ],
        ),
      ),
    );
  }

  TableRow _tableHeader(List<String> headers) {
    return TableRow(
      decoration: BoxDecoration(
          color: Theme.of(context).colorScheme.surfaceContainerHighest),
      children: headers
          .map((h) => Padding(
                padding: const EdgeInsets.all(8),
                child: Text(h,
                    style: const TextStyle(fontWeight: FontWeight.w600)),
              ))
          .toList(),
    );
  }

  TableRow _timingRow(String op, BigInt ms) {
    return TableRow(children: [
      Padding(padding: const EdgeInsets.all(8), child: Text(op)),
      Padding(
        padding: const EdgeInsets.all(8),
        child: Text(ms.toString(),
            style: const TextStyle(fontFamily: 'monospace'),
            textAlign: TextAlign.right),
      ),
    ]);
  }

  TableRow _sizeRow(String artifact, BigInt bytes) {
    final b = bytes.toInt();
    final formatted = b < 1024
        ? '$b B'
        : b < 1024 * 1024
            ? '${(b / 1024).toStringAsFixed(2)} KB'
            : '${(b / (1024 * 1024)).toStringAsFixed(2)} MB';
    return TableRow(children: [
      Padding(padding: const EdgeInsets.all(8), child: Text(artifact)),
      Padding(
        padding: const EdgeInsets.all(8),
        child: Text(formatted,
            style: const TextStyle(fontFamily: 'monospace'),
            textAlign: TextAlign.right),
      ),
    ]);
  }
}

import 'package:flutter/material.dart';

import 'package:openac/assets.dart';

import 'package:mopro_flutter_bindings/src/rust/frb_generated.dart';
import 'package:mopro_flutter_bindings/src/rust/third_party/openac_mobile_app.dart'
    show
        BenchmarkResults,
        ProofResult,
        generateSharedBlinds,
        proveJwt,
        proveShow,
        reblindJwt,
        reblindShow,
        runCompleteBenchmark,
        setupJwtKeys,
        setupShowKeys,
        verifyJwt,
        verifyShow;

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();
  await prepareAssets();
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      theme: ThemeData(primarySwatch: Colors.blue, useMaterial3: true),
      home: const E2EProofWorkflowScreen(),
    );
  }
}

class E2EProofWorkflowScreen extends StatefulWidget {
  const E2EProofWorkflowScreen({super.key});

  @override
  State<E2EProofWorkflowScreen> createState() =>
      _E2EProofWorkflowScreenState();
}

enum ProofTaskType {
  setupJwt,
  setupShow,
  generateBlinds,
  proveJwt,
  proveShow,
  reblindJwt,
  reblindShow,
  verifyJwt,
  verifyShow,
}

class TaskResult {
  final ProofTaskType taskType;
  final bool success;
  final String? error;
  final ProofResult? proofResult;
  final String? message;
  final bool? verifyResult;
  final int? clientTimingMs;

  TaskResult({
    required this.taskType,
    required this.success,
    this.error,
    this.proofResult,
    this.message,
    this.verifyResult,
    this.clientTimingMs,
  });

  BigInt? get totalMs =>
      proofResult?.totalMs ??
      (clientTimingMs != null ? BigInt.from(clientTimingMs!) : null);
  BigInt? get proofSizeBytes => proofResult?.proofSizeBytes;
  String? get commWShared => proofResult?.commWShared;
}

class _E2EProofWorkflowScreenState extends State<E2EProofWorkflowScreen> {
  bool _isOperating = false;
  Exception? _error;

  Map<String, TaskResult> _results = {};
  Map<String, bool> _completedSteps = {};
  BenchmarkResults? _benchmarkResults;

  bool _workflowRunning = false;
  String? _currentWorkflowStep;

  /// Execute a single proof step and return its result.
  /// All Rust functions resolve their own input paths from documents_path;
  /// no inputPath parameter is passed.
  Future<TaskResult> _executeStep(
      ProofTaskType taskType, String documentsPath) async {
    switch (taskType) {
      case ProofTaskType.setupJwt:
        final t = DateTime.now();
        final msg = await setupJwtKeys(documentsPath: documentsPath);
        return TaskResult(
          taskType: taskType,
          success: true,
          message: msg,
          clientTimingMs: DateTime.now().difference(t).inMilliseconds,
        );

      case ProofTaskType.setupShow:
        final t = DateTime.now();
        final msg = await setupShowKeys(documentsPath: documentsPath);
        return TaskResult(
          taskType: taskType,
          success: true,
          message: msg,
          clientTimingMs: DateTime.now().difference(t).inMilliseconds,
        );

      case ProofTaskType.generateBlinds:
        final t = DateTime.now();
        final msg = await generateSharedBlinds(documentsPath: documentsPath);
        return TaskResult(
          taskType: taskType,
          success: true,
          message: msg,
          clientTimingMs: DateTime.now().difference(t).inMilliseconds,
        );

      case ProofTaskType.proveJwt:
        final pr = await proveJwt(documentsPath: documentsPath);
        return TaskResult(
          taskType: taskType,
          success: true,
          proofResult: pr,
        );

      case ProofTaskType.proveShow:
        final pr = await proveShow(documentsPath: documentsPath);
        return TaskResult(
          taskType: taskType,
          success: true,
          proofResult: pr,
        );

      case ProofTaskType.reblindJwt:
        final pr = await reblindJwt(documentsPath: documentsPath);
        return TaskResult(
          taskType: taskType,
          success: true,
          proofResult: pr,
        );

      case ProofTaskType.reblindShow:
        final pr = await reblindShow(documentsPath: documentsPath);
        return TaskResult(
          taskType: taskType,
          success: true,
          proofResult: pr,
        );

      case ProofTaskType.verifyJwt:
        final t = DateTime.now();
        final ok = await verifyJwt(documentsPath: documentsPath);
        return TaskResult(
          taskType: taskType,
          success: ok,
          verifyResult: ok,
          clientTimingMs: DateTime.now().difference(t).inMilliseconds,
        );

      case ProofTaskType.verifyShow:
        final t = DateTime.now();
        final ok = await verifyShow(documentsPath: documentsPath);
        return TaskResult(
          taskType: taskType,
          success: ok,
          verifyResult: ok,
          clientTimingMs: DateTime.now().difference(t).inMilliseconds,
        );
    }
  }

  Future<void> _runOperation(ProofTaskType taskType) async {
    setState(() {
      _isOperating = true;
      _error = null;
    });
    try {
      final docs = await getDocumentsPath();
      final result = await _executeStep(taskType, docs);
      setState(() {
        _results[taskType.name] = result;
        _completedSteps[taskType.name] = result.success;
        _isOperating = false;
      });
    } catch (e) {
      setState(() {
        _results[taskType.name] =
            TaskResult(taskType: taskType, success: false, error: e.toString());
        _completedSteps[taskType.name] = false;
        _error = Exception('${_taskTypeToDisplayName(taskType)} failed: $e');
        _isOperating = false;
      });
    }
  }

  /// Run the full 9-step workflow sequentially, matching e2e_full_workflow in lib.rs:
  ///   setup_jwt → setup_show → generate_blinds →
  ///   prove_jwt → reblind_jwt → prove_show → reblind_show →
  ///   verify_jwt → verify_show
  Future<void> _runE2EWorkflow() async {
    setState(() {
      _isOperating = true;
      _workflowRunning = true;
      _error = null;
      _results = {};
      _completedSteps = {};
      _currentWorkflowStep = null;
    });

    final docs = await getDocumentsPath();

    const steps = [
      ProofTaskType.setupJwt,
      ProofTaskType.setupShow,
      ProofTaskType.generateBlinds,
      ProofTaskType.proveJwt,
      ProofTaskType.reblindJwt,
      ProofTaskType.proveShow,
      ProofTaskType.reblindShow,
      ProofTaskType.verifyJwt,
      ProofTaskType.verifyShow,
    ];

    for (int i = 0; i < steps.length; i++) {
      final step = steps[i];
      setState(() {
        _currentWorkflowStep =
            '${i + 1}/${steps.length}: ${_taskTypeToDisplayName(step)}';
      });

      try {
        final result = await _executeStep(step, docs);
        setState(() {
          _results[step.name] = result;
          _completedSteps[step.name] = result.success;
        });
        if (!result.success) {
          setState(() {
            _error = Exception(
                'Workflow stopped: ${_taskTypeToDisplayName(step)} failed');
            _isOperating = false;
            _workflowRunning = false;
            _currentWorkflowStep = null;
          });
          return;
        }
      } catch (e) {
        setState(() {
          _results[step.name] =
              TaskResult(taskType: step, success: false, error: e.toString());
          _completedSteps[step.name] = false;
          _error = Exception(
              'Workflow stopped at ${_taskTypeToDisplayName(step)}: $e');
          _isOperating = false;
          _workflowRunning = false;
          _currentWorkflowStep = null;
        });
        return;
      }
    }

    setState(() {
      _isOperating = false;
      _workflowRunning = false;
      _currentWorkflowStep = null;
    });
  }

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

  void _reset() {
    setState(() {
      _results = {};
      _completedSteps = {};
      _error = null;
      _isOperating = false;
      _benchmarkResults = null;
      _workflowRunning = false;
      _currentWorkflowStep = null;
    });
  }

  String _taskTypeToDisplayName(ProofTaskType type) {
    return switch (type) {
      ProofTaskType.setupJwt => 'Setup JWT Keys',
      ProofTaskType.setupShow => 'Setup Show Keys',
      ProofTaskType.generateBlinds => 'Generate Shared Blinds',
      ProofTaskType.proveJwt => 'Prove JWT',
      ProofTaskType.proveShow => 'Prove Show',
      ProofTaskType.reblindJwt => 'Reblind JWT',
      ProofTaskType.reblindShow => 'Reblind Show',
      ProofTaskType.verifyJwt => 'Verify JWT',
      ProofTaskType.verifyShow => 'Verify Show',
    };
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('OpenAC E2E Proof Workflow'),
        actions: [
          if (_results.isNotEmpty && !_isOperating)
            IconButton(
              icon: const Icon(Icons.refresh),
              onPressed: _reset,
              tooltip: 'Reset',
            ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            if (_error != null)
              Card(
                color: Colors.red.shade50,
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Row(
                    children: [
                      Icon(Icons.error, color: Colors.red.shade700),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          _error.toString(),
                          style: TextStyle(color: Colors.red.shade900),
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

            // ── E2E Full Workflow ──────────────────────────────────────────
            Card(
              elevation: 4,
              color: Colors.indigo.shade50,
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Icon(Icons.play_circle_filled,
                            color: Colors.indigo.shade700),
                        const SizedBox(width: 8),
                        const Text(
                          'E2E Full Workflow',
                          style: TextStyle(
                              fontSize: 18, fontWeight: FontWeight.bold),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    const Text(
                      'Runs all 9 steps sequentially: setup → generate blinds → prove → reblind → verify for both circuits.',
                      style: TextStyle(fontSize: 12, color: Colors.grey),
                    ),
                    if (_workflowRunning && _currentWorkflowStep != null) ...[
                      const SizedBox(height: 12),
                      Row(
                        children: [
                          const SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          ),
                          const SizedBox(width: 8),
                          Text(
                            _currentWorkflowStep!,
                            style: TextStyle(
                              fontWeight: FontWeight.w500,
                              color: Colors.indigo.shade700,
                            ),
                          ),
                        ],
                      ),
                    ],
                    const SizedBox(height: 12),
                    SizedBox(
                      width: double.infinity,
                      child: ElevatedButton.icon(
                        onPressed: _isOperating ? null : _runE2EWorkflow,
                        style: ElevatedButton.styleFrom(
                          backgroundColor: Colors.indigo,
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.all(16),
                        ),
                        icon: _workflowRunning
                            ? const SizedBox(
                                width: 20,
                                height: 20,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                  valueColor: AlwaysStoppedAnimation<Color>(
                                      Colors.white),
                                ),
                              )
                            : const Icon(Icons.play_circle_filled),
                        label: Text(_workflowRunning
                            ? 'Running Workflow...'
                            : 'Run E2E Workflow (9 steps)'),
                      ),
                    ),
                  ],
                ),
              ),
            ),

            const SizedBox(height: 16),

            // ── Complete Benchmark ─────────────────────────────────────────
            Card(
              elevation: 4,
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Row(
                      children: [
                        Icon(Icons.speed, color: Colors.deepPurple),
                        SizedBox(width: 8),
                        Text(
                          'Complete Benchmark',
                          style: TextStyle(
                              fontSize: 18, fontWeight: FontWeight.bold),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    const Text(
                      'Runs all 9 operations and reports timing + artifact sizes.',
                      style: TextStyle(fontSize: 12, color: Colors.grey),
                    ),
                    const SizedBox(height: 12),
                    SizedBox(
                      width: double.infinity,
                      child: ElevatedButton.icon(
                        onPressed: _isOperating ? null : _runBenchmark,
                        style: ElevatedButton.styleFrom(
                          backgroundColor: Colors.deepPurple,
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.all(16),
                        ),
                        icon: _isOperating
                            ? const SizedBox(
                                width: 20,
                                height: 20,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                  valueColor: AlwaysStoppedAnimation<Color>(
                                      Colors.white),
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

            const SizedBox(height: 24),
            const Divider(),
            const SizedBox(height: 16),

            // ── Step 1: Key Setup ──────────────────────────────────────────
            _buildSectionHeader('Step 1: Key Setup', Icons.settings),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: _buildOperationButton(
                    taskType: ProofTaskType.setupJwt,
                    label: 'Setup JWT',
                    icon: Icons.key,
                    color: Colors.blue,
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: _buildOperationButton(
                    taskType: ProofTaskType.setupShow,
                    label: 'Setup Show',
                    icon: Icons.key,
                    color: Colors.blue,
                  ),
                ),
              ],
            ),

            const SizedBox(height: 24),

            // ── Step 2: Generate Shared Blinds ─────────────────────────────
            _buildSectionHeader(
                'Step 2: Generate Shared Blinds', Icons.shuffle),
            const SizedBox(height: 12),
            _buildOperationButton(
              taskType: ProofTaskType.generateBlinds,
              label: 'Generate Shared Blinds',
              icon: Icons.shuffle,
              color: Colors.orange,
            ),

            const SizedBox(height: 24),

            // ── Step 3: JWT ────────────────────────────────────────────────
            _buildSectionHeader('Step 3: JWT', Icons.assignment),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: _buildOperationButton(
                    taskType: ProofTaskType.proveJwt,
                    label: 'Prove JWT',
                    icon: Icons.calculate,
                    color: Colors.green,
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: _buildOperationButton(
                    taskType: ProofTaskType.reblindJwt,
                    label: 'Reblind JWT',
                    icon: Icons.sync,
                    color: Colors.green,
                  ),
                ),
              ],
            ),

            const SizedBox(height: 24),

            // ── Step 4: Show ───────────────────────────────────────────────
            _buildSectionHeader('Step 4: Show', Icons.visibility),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: _buildOperationButton(
                    taskType: ProofTaskType.proveShow,
                    label: 'Prove Show',
                    icon: Icons.calculate,
                    color: Colors.deepPurple,
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: _buildOperationButton(
                    taskType: ProofTaskType.reblindShow,
                    label: 'Reblind Show',
                    icon: Icons.sync,
                    color: Colors.deepPurple,
                  ),
                ),
              ],
            ),

            const SizedBox(height: 24),

            // ── Step 5: Verify ─────────────────────────────────────────────
            _buildSectionHeader('Step 5: Verify Proofs', Icons.check_circle),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: _buildOperationButton(
                    taskType: ProofTaskType.verifyJwt,
                    label: 'Verify JWT',
                    icon: Icons.check_circle,
                    color: Colors.teal,
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: _buildOperationButton(
                    taskType: ProofTaskType.verifyShow,
                    label: 'Verify Show',
                    icon: Icons.check_circle,
                    color: Colors.teal,
                  ),
                ),
              ],
            ),

            const SizedBox(height: 24),
            const Divider(),
            const SizedBox(height: 16),

            // ── Results ────────────────────────────────────────────────────
            if (_results.isNotEmpty) ...[
              _buildSectionHeader('Results', Icons.assessment),
              const SizedBox(height: 12),
              ..._results.entries.map((e) => _buildResultCard(e.key, e.value)),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildSectionHeader(String title, IconData icon) {
    return Row(
      children: [
        Icon(icon, color: Colors.grey.shade700),
        const SizedBox(width: 8),
        Text(
          title,
          style: TextStyle(
            fontSize: 18,
            fontWeight: FontWeight.bold,
            color: Colors.grey.shade800,
          ),
        ),
      ],
    );
  }

  Widget _buildOperationButton({
    required ProofTaskType taskType,
    required String label,
    required IconData icon,
    required MaterialColor color,
  }) {
    final isCompleted = _completedSteps[taskType.name] == true;
    final result = _results[taskType.name];

    return ElevatedButton.icon(
      onPressed: _isOperating ? null : () => _runOperation(taskType),
      style: ElevatedButton.styleFrom(
        backgroundColor: isCompleted ? color.shade100 : color,
        foregroundColor: isCompleted ? color.shade900 : Colors.white,
        padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 16),
      ),
      icon: isCompleted
          ? Icon(Icons.check_circle, color: color.shade700)
          : Icon(icon),
      label: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(label),
          if (result?.totalMs != null)
            Text(
              '${result!.totalMs}ms',
              style: TextStyle(
                fontSize: 11,
                color: isCompleted ? color.shade700 : Colors.white70,
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildResultCard(String taskName, TaskResult result) {
    final taskType =
        ProofTaskType.values.firstWhere((e) => e.name == taskName);
    final displayName = _taskTypeToDisplayName(taskType);

    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  result.success ? Icons.check_circle : Icons.error,
                  color: result.success ? Colors.green : Colors.red,
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    displayName,
                    style: const TextStyle(
                        fontSize: 16, fontWeight: FontWeight.bold),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),

            if (result.error != null) ...[
              Text('Error: ${result.error}',
                  style: TextStyle(color: Colors.red.shade700)),
              const SizedBox(height: 8),
            ],

            if (result.message != null) ...[
              Text(result.message!),
              const SizedBox(height: 8),
            ],

            if (result.totalMs != null) ...[
              const Text('Timing:',
                  style: TextStyle(fontWeight: FontWeight.bold)),
              const SizedBox(height: 4),
              Text('• Total: ${result.totalMs}ms'),
              const SizedBox(height: 8),
            ],

            if (result.proofSizeBytes != null) ...[
              Text(
                'Proof Size: ${(result.proofSizeBytes!.toInt() / 1024).toStringAsFixed(2)} KB',
                style: TextStyle(color: Colors.grey.shade700),
              ),
              const SizedBox(height: 8),
            ],

            if (result.commWShared != null) ...[
              const Text('Shared Commitment:',
                  style: TextStyle(fontWeight: FontWeight.bold)),
              const SizedBox(height: 4),
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: Colors.grey.shade100,
                  borderRadius: BorderRadius.circular(4),
                ),
                child: SelectableText(
                  result.commWShared!,
                  style: TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 12,
                    color: Colors.grey.shade800,
                  ),
                ),
              ),
            ],

            if (result.verifyResult != null) ...[
              const SizedBox(height: 8),
              Text(
                result.verifyResult!
                    ? 'Verification passed ✓'
                    : 'Verification failed ✗',
                style: TextStyle(
                  color: result.verifyResult!
                      ? Colors.green.shade700
                      : Colors.red.shade700,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildBenchmarkResults() {
    if (_benchmarkResults == null) return const SizedBox.shrink();
    final r = _benchmarkResults!;

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
                const Row(
                  children: [
                    Icon(Icons.assessment, color: Colors.deepPurple),
                    SizedBox(width: 8),
                    Text('Benchmark Results',
                        style: TextStyle(
                            fontSize: 18, fontWeight: FontWeight.bold)),
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

            const Text('Timing Metrics',
                style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                    color: Colors.deepPurple)),
            const SizedBox(height: 8),
            Table(
              border: TableBorder.all(color: Colors.grey.shade300),
              columnWidths: const {
                0: FlexColumnWidth(2),
                1: FlexColumnWidth(1),
              },
              children: [
                _tableHeader(['Operation', 'Time (ms)']),
                _timingRow('JWT Setup', r.jwtSetupMs),
                _timingRow('Show Setup', r.showSetupMs),
                _timingRow('Generate Blinds', r.generateBlindsMs),
                _timingRow('Prove JWT', r.proveJwtMs),
                _timingRow('Reblind JWT', r.reblindJwtMs),
                _timingRow('Prove Show', r.proveShowMs),
                _timingRow('Reblind Show', r.reblindShowMs),
                _timingRow('Verify JWT', r.verifyJwtMs),
                _timingRow('Verify Show', r.verifyShowMs),
              ],
            ),

            const SizedBox(height: 24),
            const Text('Artifact Sizes',
                style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                    color: Colors.deepPurple)),
            const SizedBox(height: 8),
            Table(
              border: TableBorder.all(color: Colors.grey.shade300),
              columnWidths: const {
                0: FlexColumnWidth(2),
                1: FlexColumnWidth(1),
              },
              children: [
                _tableHeader(['Artifact', 'Size']),
                _sizeRow('JWT Proving Key', r.jwtProvingKeyBytes),
                _sizeRow('JWT Verifying Key', r.jwtVerifyingKeyBytes),
                _sizeRow('Show Proving Key', r.showProvingKeyBytes),
                _sizeRow('Show Verifying Key', r.showVerifyingKeyBytes),
                _sizeRow('JWT Proof', r.jwtProofBytes),
                _sizeRow('Show Proof', r.showProofBytes),
                _sizeRow('JWT Witness', r.jwtWitnessBytes),
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
      decoration: BoxDecoration(color: Colors.grey.shade200),
      children: headers
          .map((h) => Padding(
                padding: const EdgeInsets.all(8),
                child: Text(h,
                    style: const TextStyle(
                        fontWeight: FontWeight.bold, fontSize: 14)),
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

import 'package:flutter/material.dart';

import 'assets.dart';
import 'flow/flow_backend.dart';
import 'flow/flow_models.dart';
import 'flow/flow_screen.dart';

/// Hosts the flow and the benchmark. Only the selected tab is built, so
/// leaving Flow disposes it and unloads its keys; the benchmark overwrites
/// the same key files.
class HomeShell extends StatefulWidget {
  const HomeShell({
    super.key,
    required this.backend,
    required this.benchmarkBuilder,
    this.loadBundle = loadFlowBundle,
    this.assetsError,
  });

  final FlowBackend backend;
  final Widget Function(ValueNotifier<bool> busy) benchmarkBuilder;
  final Future<FlowBundle> Function() loadBundle;
  final String? assetsError;

  @override
  State<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends State<HomeShell> {
  final _busy = ValueNotifier(false);
  late final _backend = _UnloadTracker(widget.backend);
  int _index = 0;

  @override
  void dispose() {
    _busy.dispose();
    super.dispose();
  }

  Future<void> _select(int i) async {
    if (_busy.value) return;
    final leavingFlow = _index == 0 && i != 0;
    if (leavingFlow) _busy.value = true;
    setState(() => _index = i);
    if (!leavingFlow) return;
    // The controller's dispose starts the unload while the next frame builds.
    await WidgetsBinding.instance.endOfFrame;
    await _backend.pendingUnload;
    if (mounted) _busy.value = false;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Column(
        children: [
          if (widget.assetsError != null)
            MaterialBanner(
              content: Text(widget.assetsError!),
              backgroundColor: Theme.of(context).colorScheme.errorContainer,
              actions: const [SizedBox.shrink()],
            ),
          Expanded(
            child: _index == 0
                ? FlowScreen(
                    backend: _backend,
                    loadBundle: widget.loadBundle,
                    busy: _busy,
                  )
                : widget.benchmarkBuilder(_busy),
          ),
        ],
      ),
      bottomNavigationBar: ValueListenableBuilder<bool>(
        valueListenable: _busy,
        builder: (context, busy, _) => IgnorePointer(
          ignoring: busy,
          child: Opacity(
            opacity: busy ? 0.5 : 1,
            child: NavigationBar(
              selectedIndex: _index,
              onDestinationSelected: _select,
              destinations: const [
                NavigationDestination(
                    icon: Icon(Icons.verified_user_outlined),
                    selectedIcon: Icon(Icons.verified_user),
                    label: 'Flow'),
                NavigationDestination(
                    icon: Icon(Icons.speed_outlined),
                    selectedIcon: Icon(Icons.speed),
                    label: 'Benchmark'),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

/// Remembers the latest unload so the shell can wait on a call the flow
/// controller starts without awaiting.
class _UnloadTracker implements FlowBackend {
  _UnloadTracker(this._inner);

  final FlowBackend _inner;
  Future<void> pendingUnload = Future.value();

  @override
  Future<void> unload() => pendingUnload = _inner.unload();

  @override
  Future<KeysInfo> ensureKeys() => _inner.ensureKeys();

  @override
  Future<PrepareOutcome> prepare() => _inner.prepare();

  @override
  Future<Presentation> present(FlowRequest request) => _inner.present(request);

  @override
  Future<VerifyOutcome> verify(Presentation p, FlowRequest against) =>
      _inner.verify(p, against);
}

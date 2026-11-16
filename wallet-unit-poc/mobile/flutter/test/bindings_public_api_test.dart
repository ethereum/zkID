import 'package:flutter_test/flutter_test.dart';
import 'package:mopro_flutter_bindings/mopro_flutter_bindings.dart';

// Compiling the public library is the check: the app imports it, and
// `flutter analyze` does not report errors inside a path dependency.
void main() {
  test('public library exposes the flow API', () {
    final api = <Function>[
      flowPrepare,
      flowPresent,
      flowVerify,
      flowUnload,
      loadPrepareKey,
      loadShowKey,
      zkErrorMessage,
    ];
    expect(api, everyElement(isNotNull));
  });
}

import 'dart:convert';

import 'package:mopro_flutter_bindings/src/rust/third_party/openac_mobile_app.dart'
    show currentRssKb, peakRssKb, resetPeakRss;

// logcat truncates lines near 1 KiB; the parsers read one JSON per line.
const maxLineBytes = 900;

// Error text is cut by UTF-8 bytes, then shrunk until the whole line fits.
const _maxErrorBytes = 300;

void printLine(String line) {
  // ignore: avoid_print
  print(line);
}

/// Prints an `<prefix>ERROR` line. [fields] identify the failing unit
/// (`config` for the Firebase configs, `step` for bench_config.json runs).
void logError(String prefix, Map<String, Object?> fields, Object error) {
  var bytes = utf8.encode(error.toString());
  if (bytes.length > _maxErrorBytes) bytes = bytes.sublist(0, _maxErrorBytes);
  while (true) {
    final line = '${prefix}ERROR ${jsonEncode({
          ...fields,
          'error': utf8.decode(bytes, allowMalformed: true),
        })}';
    if (utf8.encode(line).length < maxLineBytes || bytes.isEmpty) {
      printLine(line);
      return;
    }
    bytes = bytes.sublist(0, bytes.length * 4 ~/ 5);
  }
}

/// Prints one marker line. A line too long for logcat is replaced by an
/// ERROR line and reported as false; this never throws.
bool logMarker(String marker, Map<String, Object?> obj,
    {required String errorPrefix, required Map<String, Object?> errorFields}) {
  final line = '$marker ${jsonEncode(obj)}';
  if (utf8.encode(line).length >= maxLineBytes) {
    logError(
        errorPrefix, errorFields, '$marker line exceeds $maxLineBytes bytes');
    return false;
  }
  printLine(line);
  return true;
}

int toInt(BigInt v) => v.toInt();

class Probe<T> {
  final T out;
  final int baseKb;
  final int peakKb;
  final bool perStep;
  Probe(this.out, this.baseKb, this.peakKb, this.perStep);
}

/// Runs [f] with the kernel peak-RSS mark reset, so the peak covers only [f].
Future<Probe<T>> probe<T>(Future<T> Function() f) async {
  final base = toInt(await currentRssKb());
  final perStep = await resetPeakRss();
  final out = await f();
  return Probe(out, base, toInt(await peakRssKb()), perStep);
}

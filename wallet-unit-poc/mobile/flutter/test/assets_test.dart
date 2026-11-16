import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:openac/assets.dart';

ByteData bytes(List<int> b) => ByteData.sublistView(Uint8List.fromList(b));

void main() {
  late Directory dir;
  late String manifest;
  late List<String> loaded;

  Future<ByteData> load(String key) async {
    loaded.add(key);
    if (key.endsWith('manifest.json')) return bytes(utf8.encode(manifest));
    if (key.endsWith('.r1cs.gz')) {
      return bytes(gzip.encode(utf8.encode('r1cs for $key')));
    }
    if (key.endsWith('.json')) return bytes(utf8.encode('{"from":"$key"}'));
    throw MissingAssetsException(key);
  }

  File f(String rel) => File('${dir.path}/$rel');

  setUp(() {
    dir = Directory.systemTemp.createTempSync('assets_test');
    manifest = '{"build":1}';
    loaded = [];
  });
  tearDown(() => dir.deleteSync(recursive: true));

  test('first run extracts r1cs, inputs and the manifest', () async {
    await extractAssets(dir, load: load);
    expect(f('build/jwt/jwt_js/jwt.r1cs').existsSync(), isTrue);
    expect(f('build/show/show_js/show.r1cs').existsSync(), isTrue);
    expect(f('jwt_input.json').readAsStringSync(), contains('jwt_input'));
    expect(f('manifest.json').readAsStringSync(), manifest);
  });

  test('an unchanged manifest keeps r1cs and keys, but refreshes inputs',
      () async {
    await extractAssets(dir, load: load);
    f('keys/pk').createSync(recursive: true);
    f('jwt_input.json').writeAsStringSync('stale');
    loaded.clear();

    await extractAssets(dir, load: load);
    expect(f('keys/pk').existsSync(), isTrue);
    expect(loaded.where((k) => k.endsWith('.gz')), isEmpty);
    expect(f('jwt_input.json').readAsStringSync(), contains('jwt_input'));
  });

  test('a changed manifest drops stale r1cs and keys', () async {
    await extractAssets(dir, load: load);
    f('keys/pk').createSync(recursive: true);
    f('build/jwt/jwt_js/jwt.r1cs').writeAsStringSync('stale r1cs');

    manifest = '{"build":2}';
    await extractAssets(dir, load: load);
    expect(f('keys/pk').existsSync(), isFalse);
    expect(f('build/jwt/jwt_js/jwt.r1cs').readAsStringSync(),
        'r1cs for assets/circom/jwt.r1cs.gz');
    expect(f('manifest.json').readAsStringSync(), manifest);
  });

  test('a missing local manifest also resets', () async {
    await extractAssets(dir, load: load);
    f('keys/pk').createSync(recursive: true);
    f('manifest.json').deleteSync();

    await extractAssets(dir, load: load);
    expect(f('keys/pk').existsSync(), isFalse);
  });

  test('a missing bundled asset names the prepare script', () async {
    Future<ByteData> missing(String key) async =>
        throw MissingAssetsException(key);
    expect(
      () => extractAssets(dir, load: missing),
      throwsA(isA<MissingAssetsException>().having(
          (e) => e.toString(), 'message', contains('prepare-assets.sh'))),
    );
  });
}

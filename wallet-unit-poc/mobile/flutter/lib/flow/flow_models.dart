/// Schema 1 of `assets/flow/bundle.json`, written by `scripts/prepare-assets.sh`.
class FlowBundle {
  final int schemaVersion;
  final String sdkVersion;
  final CircuitInfo circuit;
  final FlowCredential credential;
  final List<FlowRequest> requests;
  final List<FlowScenario> scenarios;

  const FlowBundle({
    required this.schemaVersion,
    required this.sdkVersion,
    required this.circuit,
    required this.credential,
    required this.requests,
    required this.scenarios,
  });

  factory FlowBundle.fromJson(Map<String, dynamic> json) {
    final version = json['schemaVersion'] as int;
    if (version != 1) {
      throw FormatException('Unsupported flow bundle schema $version');
    }
    final bundle = FlowBundle(
      schemaVersion: version,
      sdkVersion: json['sdkVersion'] as String,
      circuit: CircuitInfo.fromJson(json['circuit'] as Map<String, dynamic>),
      credential:
          FlowCredential.fromJson(json['credential'] as Map<String, dynamic>),
      requests: [
        for (final r in json['requests'] as List)
          FlowRequest.fromJson(r as Map<String, dynamic>),
      ],
      scenarios: [
        for (final s in json['scenarios'] as List)
          FlowScenario.fromJson(s as Map<String, dynamic>),
      ],
    );
    for (final s in bundle.scenarios) {
      for (final id in [s.presentFor, s.verifyAgainst]) {
        if (!bundle.requests.any((r) => r.id == id)) {
          throw FormatException(
              'Scenario ${s.id} refers to unknown request $id');
        }
      }
    }
    return bundle;
  }

  FlowRequest request(String id) => requests.firstWhere((r) => r.id == id);
}

class CircuitInfo {
  final String size;
  final String jwtR1csSha256;
  final String showR1csSha256;
  final String sourceCommit;

  const CircuitInfo({
    required this.size,
    required this.jwtR1csSha256,
    required this.showR1csSha256,
    required this.sourceCommit,
  });

  factory CircuitInfo.fromJson(Map<String, dynamic> json) => CircuitInfo(
        size: json['size'] as String,
        jwtR1csSha256: json['jwtR1csSha256'] as String,
        showR1csSha256: json['showR1csSha256'] as String,
        sourceCommit: json['sourceCommit'] as String,
      );
}

class PublicJwk {
  final String kty;
  final String crv;
  final String x;
  final String y;

  const PublicJwk({
    required this.kty,
    required this.crv,
    required this.x,
    required this.y,
  });

  factory PublicJwk.fromJson(Map<String, dynamic> json) => PublicJwk(
        kty: json['kty'] as String,
        crv: json['crv'] as String,
        x: json['x'] as String,
        y: json['y'] as String,
      );
}

class Claim {
  final String name;
  final String value;

  const Claim({required this.name, required this.value});
}

class FlowCredential {
  final String format;
  final String jwt;
  final List<String> disclosures;
  final Map<String, dynamic> header;
  final Map<String, dynamic> payload;
  final List<Claim> claims;
  final String issuer;
  final PublicJwk issuerKey;
  final PublicJwk deviceKey;

  const FlowCredential({
    required this.format,
    required this.jwt,
    required this.disclosures,
    required this.header,
    required this.payload,
    required this.claims,
    required this.issuer,
    required this.issuerKey,
    required this.deviceKey,
  });

  factory FlowCredential.fromJson(Map<String, dynamic> json) {
    final issuer = json['issuer'] as Map<String, dynamic>;
    final device = json['deviceKey'] as Map<String, dynamic>;
    return FlowCredential(
      format: json['format'] as String,
      jwt: json['jwt'] as String,
      disclosures: List<String>.from(json['disclosures'] as List),
      header: json['header'] as Map<String, dynamic>,
      payload: json['payload'] as Map<String, dynamic>,
      claims: [
        for (final c in json['claims'] as List)
          Claim(
            name: (c as Map<String, dynamic>)['name'] as String,
            value: c['value'].toString(),
          ),
      ],
      issuer: issuer['iss'] as String,
      issuerKey:
          PublicJwk.fromJson(issuer['publicKeyJwk'] as Map<String, dynamic>),
      deviceKey:
          PublicJwk.fromJson(device['publicKeyJwk'] as Map<String, dynamic>),
    );
  }
}

/// A verifier's request: what to prove, and the statement the verifier
/// expects the proofs to carry.
class FlowRequest {
  final String id;
  final String verifier;
  final String title;
  final String policyText;
  final String nonce;

  /// Show circuit input object, written to a file for the Rust side.
  final Map<String, dynamic> showInput;

  /// Decimal strings. `[0]`/`[1]` are the trusted issuer key, the rest is the
  /// claim normalization.
  final List<String> preparePublicValues;

  /// Decimal strings: the nonce hash followed by the policy.
  final List<String> showStatement;
  final bool expectedExpressionResult;

  const FlowRequest({
    required this.id,
    required this.verifier,
    required this.title,
    required this.policyText,
    required this.nonce,
    required this.showInput,
    required this.preparePublicValues,
    required this.showStatement,
    required this.expectedExpressionResult,
  });

  factory FlowRequest.fromJson(Map<String, dynamic> json) {
    final expected = json['expected'] as Map<String, dynamic>;
    return FlowRequest(
      id: json['id'] as String,
      verifier: json['verifier'] as String,
      title: json['title'] as String,
      policyText: json['policyText'] as String,
      nonce: json['nonce'] as String,
      showInput: json['showInput'] as Map<String, dynamic>,
      preparePublicValues:
          List<String>.from(expected['preparePublicValues'] as List),
      showStatement: List<String>.from(expected['showStatement'] as List),
      expectedExpressionResult: json['expectedExpressionResult'] as bool,
    );
  }
}

enum ExpectedOutcome {
  accepted('accepted', Verdict.verified),
  policyFalse('policy_false', Verdict.policyNotSatisfied),
  rejected('rejected', Verdict.rejected);

  final String wire;
  final Verdict verdict;

  const ExpectedOutcome(this.wire, this.verdict);

  static ExpectedOutcome parse(String wire) =>
      values.firstWhere((e) => e.wire == wire,
          orElse: () => throw FormatException('Unknown expect "$wire"'));
}

enum Verdict {
  verified('VERIFIED'),
  policyNotSatisfied('POLICY NOT SATISFIED'),
  rejected('REJECTED');

  final String label;

  const Verdict(this.label);

  static Verdict of({required bool valid, required bool expressionResult}) {
    if (!valid) return rejected;
    return expressionResult ? verified : policyNotSatisfied;
  }
}

class FlowScenario {
  final String id;
  final String title;
  final String description;
  final String presentFor;
  final String verifyAgainst;
  final ExpectedOutcome expect;

  const FlowScenario({
    required this.id,
    required this.title,
    required this.description,
    required this.presentFor,
    required this.verifyAgainst,
    required this.expect,
  });

  factory FlowScenario.fromJson(Map<String, dynamic> json) => FlowScenario(
        id: json['id'] as String,
        title: json['title'] as String,
        description: json['description'] as String,
        presentFor: json['presentFor'] as String,
        verifyAgainst: json['verifyAgainst'] as String,
        expect: ExpectedOutcome.parse(json['expect'] as String),
      );
}

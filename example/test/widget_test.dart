// Runs on the host, with no device: the platform channel is faked, so this
// only covers what Dart is responsible for — that the list renders what the
// wallet reports.

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_wallet_example/main.dart';

const _channel = MethodChannel('dev.digitalcredentials.flutter_wallet/wallet');

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  final calls = <String>[];

  setUp(() {
    calls.clear();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(_channel, (call) async {
      calls.add(call.method);
      switch (call.method) {
        case 'listCredentials':
          return [
            {
              'id': 'id1',
              'title': "Jon's Driving License",
              'subtitle': 'Utopia DMV',
              'docType': 'org.iso.18013.5.1.mDL',
              'claims': [
                {
                  'namespace': 'org.iso.18013.5.1',
                  'identifier': 'age_over_21',
                  'displayName': 'Age Over 21',
                  'value': 'true',
                },
              ],
            },
          ];
        case 'register':
          return 1;
        case 'addCredentials':
          return <String>['id1'];
        default:
          return null;
      }
    });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(_channel, null);
  });

  testWidgets('registers on start and lists what the wallet reports',
      (tester) async {
    await tester.pumpWidget(const WalletExampleApp());
    await tester.pumpAndSettle();

    expect(calls, contains('register'));
    expect(find.text("Jon's Driving License"), findsOneWidget);
    expect(find.text('Utopia DMV'), findsOneWidget);
    expect(find.text('registered 1 credential(s)'), findsOneWidget);
  });

  testWidgets('claims appear when a credential is expanded', (tester) async {
    await tester.pumpWidget(const WalletExampleApp());
    await tester.pumpAndSettle();

    expect(find.text('Age Over 21'), findsNothing);
    await tester.tap(find.text("Jon's Driving License"));
    await tester.pumpAndSettle();

    // The issuer's label, not the raw element identifier — the distinction
    // that was wrong in the issuance sheet.
    expect(find.text('Age Over 21'), findsOneWidget);
    expect(find.text('true'), findsOneWidget);
  });
}

// Runs on a real device: `flutter test integration_test -d <device>`.
//
// Everything here needs the platform side, so there is nothing to mock — the
// point is to confirm the channel, the store and the registry work together
// on-device. The deeper properties (device signatures, issuance) need a
// verifier and an issuer, and are exercised by the sibling Python projects.

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_wallet/flutter_wallet.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  final wallet = FlutterWallet.instance;

  testWidgets('registering with Credential Manager succeeds', (tester) async {
    // Returns how many were registered; zero is legitimate on a fresh install.
    final count = await wallet.register();
    expect(count, greaterThanOrEqualTo(0));
  });

  testWidgets('listing credentials returns the stored set', (tester) async {
    final credentials = await wallet.listCredentials();
    for (final credential in credentials) {
      expect(credential.id, isNotEmpty);
      expect(credential.docType, isNotEmpty);
    }
  });

  testWidgets('a credential with no mdoc is skipped, not fatal',
      (tester) async {
    const id = 'integration-test-credential';
    final before = await wallet.listCredentials();

    await wallet.addCredentials('''
      [{
        "id": "$id",
        "config": {"format": "mso_mdoc", "doctype": "org.iso.18013.5.1.mDL"},
        "displayData": {"title": "Test", "subtitle": "Integration"},
        "credentials": []
      }]
    ''');

    // It cannot be projected without an mdoc to read claims from, so it is
    // filtered out of the list rather than crashing it. Pinning that, because
    // the alternative is a wallet that dies on one malformed entry.
    final after = await wallet.listCredentials();
    expect(after.map((c) => c.id), isNot(contains(id)));
    expect(after.length, before.length);

    await wallet.deleteCredential(id);
  });
}

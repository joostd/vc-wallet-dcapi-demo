/// A Digital Credentials wallet for Android, as a Flutter plugin.
///
/// The host app registers the wallet with Android's Credential Manager and
/// renders whatever UI it likes; everything else — mdoc construction, the
/// hardware-backed device key, the OpenID4VP response, the provider
/// activities — happens natively and is not visible from Dart.
///
/// Android only: the credential provider APIs have no equivalent elsewhere.
library;

import 'package:flutter/services.dart';

export 'src/issuance_sheet.dart' show IssuanceSheet, IssuanceOffer;

const MethodChannel _channel =
    MethodChannel('dev.digitalcredentials.flutter_wallet/wallet');

/// One claim of a credential, as it will be shown to the user.
class WalletClaim {
  const WalletClaim({
    required this.namespace,
    required this.identifier,
    required this.displayName,
    this.value,
  });

  /// e.g. `org.iso.18013.5.1`
  final String namespace;

  /// e.g. `age_over_21`
  final String identifier;

  /// The issuer's label for the claim, falling back to [identifier].
  final String displayName;

  /// String rendering of the value; null for types that have none.
  final String? value;

  factory WalletClaim.fromMap(Map<Object?, Object?> map) => WalletClaim(
        namespace: map['namespace']! as String,
        identifier: map['identifier']! as String,
        displayName: map['displayName']! as String,
        value: map['value'] as String?,
      );
}

/// A credential held by the wallet.
///
/// This is a projection, not the credential itself: the signed document, its
/// device key and the key alias never cross into Dart.
class WalletCredential {
  const WalletCredential({
    required this.id,
    required this.title,
    required this.docType,
    required this.claims,
    this.subtitle,
  });

  final String id;
  final String title;
  final String? subtitle;

  /// e.g. `org.iso.18013.5.1.mDL`
  final String docType;
  final List<WalletClaim> claims;

  factory WalletCredential.fromMap(Map<Object?, Object?> map) =>
      WalletCredential(
        id: map['id']! as String,
        title: map['title']! as String,
        subtitle: map['subtitle'] as String?,
        docType: map['docType']! as String,
        claims: (map['claims']! as List<Object?>)
            .cast<Map<Object?, Object?>>()
            .map(WalletClaim.fromMap)
            .toList(growable: false),
      );
}

class FlutterWallet {
  FlutterWallet._();

  static final FlutterWallet instance = FlutterWallet._();

  /// Publish the wallet's credentials to Android's Credential Manager.
  ///
  /// Call this once at app start. Until it has run, the wallet will not be
  /// offered when a site asks for a credential. Registration persists in Play
  /// services, so it does not need repeating per process start — but it is
  /// cheap, and calling it is how the host says "I am a wallet now".
  ///
  /// Returns the number of credentials registered.
  /// [subtitle] is the second line of the entry in the system's "save to"
  /// sheet when a site offers a credential.
  ///
  /// [title] is registered too, but observed behaviour on Android 17 / Play
  /// services 26.41 is that the sheet shows the host app's label instead, so
  /// do not rely on it.
  Future<int> register({
    String title = 'Wallet',
    String subtitle = 'Save your document to this wallet',
  }) async =>
      await _channel.invokeMethod<int>(
        'register',
        {'title': title, 'subtitle': subtitle},
      ) ??
      0;

  /// Every credential the wallet holds.
  Future<List<WalletCredential>> listCredentials() async {
    final result = await _channel.invokeMethod<List<Object?>>('listCredentials');
    return (result ?? const [])
        .cast<Map<Object?, Object?>>()
        .map(WalletCredential.fromMap)
        .toList(growable: false);
  }

  /// Store credentials from a JSON array and re-register.
  ///
  /// The format matches CMWallet's `databasenew.json`, so its test
  /// credentials can be loaded unchanged. Existing ids are replaced.
  /// Returns the ids stored.
  Future<List<String>> addCredentials(String json) async {
    final result = await _channel
        .invokeMethod<List<Object?>>('addCredentials', {'json': json});
    return (result ?? const []).cast<String>();
  }

  /// Forget a credential and re-register.
  Future<void> deleteCredential(String id) =>
      _channel.invokeMethod<void>('deleteCredential', {'id': id});
}

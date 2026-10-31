# flutter_wallet

A Digital Credentials wallet for Android, as a Flutter plugin: registers with
Credential Manager, presents mdoc credentials over OpenID4VP 1.0, and receives
them over OpenID4VCI 1.0. Device keys are hardware-backed in the Android
KeyStore.

Built as a minimal reimplementation of
[CMWallet](https://github.com/digitalcredentialsdev/CMWallet) — about 1,500
lines of Kotlin against its 5,679 — structured as a plugin so it can be
dropped into an existing Flutter app.

## Using it

```dart
// once, at app start
await FlutterWallet.instance.register();

// what the wallet holds
final credentials = await FlutterWallet.instance.listCredentials();

// load credentials from CMWallet-format JSON
await FlutterWallet.instance.addCredentials(json);
```

Route `/create` to `IssuanceSheet()` so the issuance activity has something to
show:

```dart
MaterialApp(
  routes: {
    '/': (_) => const MyHomeScreen(),
    '/create': (_) => const IssuanceSheet(),
  },
)
```

Nothing else is needed: the two provider activities, the permissions and the
issuance matcher are declared in the plugin's own manifest and assets, and
merge into the host app.

`example/` is a working host app.

## What it does, and what it does not

Verified end to end on a Pixel 8a (Android 17) against
[cocktails-v1-verifier](../cocktails-v1-verifier) and
[dmv-issuer](../dmv-issuer):

| | |
| --- | --- |
| Presentation, same-device | all six verifier checks pass |
| Presentation, cross-device (BLE hybrid) | all six pass, no wallet code involved |
| Issuance | hardware-attested key proof, credential stored |
| Issued credential, presented | all six pass with a KeyStore device key |

**Both response modes.** `dc_api` returns the `vp_token` as JSON; `dc_api.jwt`
encrypts it to the verifier's P-256 key with ECDH-ES and A128GCM or A256GCM.
HAIP 1.0 requires the encrypted one, so verifiers built on it — the EUDI
reference verifier among them — ask for nothing else.

**Android only.** The credential provider APIs have no equivalent elsewhere,
and the plugin deliberately has no platform-interface indirection.

Deliberately out of scope, each a localized add-back rather than a rewrite:

- **SD-JWT.** mdoc only.
- **Signed and multisigned requests** (`openid4vp-v1-signed`, `-multisigned`).
  Real verifiers do use these; the JWS helpers are in CMWallet's `Utils.kt`
  if they are needed.
- **The authorization-code grant, PAR, client attestation, DPoP, batch
  issuance.** The pre-authorized code flow is what issuers in this ecosystem
  actually use, and they accept a plain bearer token.
- **Phone-number verification**, payments and transaction data.
- **Trust lists.** `issuer_signature` proves a document was signed by whoever
  holds the leaf key; it does not establish who that is.

## Notes for anyone extending it

**Test credentials without an issuer.** `tools/eudi_to_wallet.py` converts an
mdoc from an [eudi-dev](https://github.com/eudi-dev/eudi-dev) wallet into the
store format, key included, so `eudi issue mdoc --wallet --doc-type …` becomes
a source of any doctype you like. Software-keyed, so it says nothing about
hardware binding — it is for exercising matching, labels and verifiers.

**There is no presentation UI to write.** Play services draws the credential
picker from the registry, so `GetCredentialActivity` has no layout — it builds
a response, shows a biometric prompt and returns. The only UI the wallet owns
is the issuance sheet, which is why that is the one activity hosted by
Flutter.

**The issuance matcher accepts only `openid4vci1.0` and `openid4vci-v1`.**
Plain `openid4vci` gets "No app found to save this information", because the
request never reaches the code that would have accepted it.

**`apps.json` is load-bearing.** `getOrigin()` returns a web origin only for
an allowlisted browser, and that origin is hashed into the session transcript.
Without it, Chrome's request yields an `android-origin:` and every verifier
rejects the device signature.

**The issued credential must be bound to the key you attested.** The wallet
checks this at issuance time, because the alternative is discovering it much
later as an unexplained "device signature invalid".

## License and attribution

Apache License 2.0 — see [LICENSE](LICENSE).

Derived from [CMWallet](https://github.com/digitalcredentialsdev/CMWallet),
the Android Digital Credentials sample wallet, which is Apache-2.0 licensed.
Three files are taken from it byte for byte:

- `LICENSE` — CMWallet's, tracked rather than adapted, down to the unfilled
  `Copyright [yyyy] [name of copyright owner]` line it also carries. If
  upstream's licence changes, copy it again; do not edit this one in place.
- `android/src/main/assets/provision_hardcoded.wasm` — the issuance matcher
  Play services runs to decide whether this wallet can accept an offer.
- `android/src/main/assets/apps.json` — the browser allowlist `getOrigin()`
  consults.

The Kotlin is a reimplementation rather than a copy, but follows CMWallet's
structure closely where the protocols leave no choice: the DCQL matching, the
`OpenID4VPDCAPIHandover` session transcript, and the mdoc `IssuerSigned`
handling.

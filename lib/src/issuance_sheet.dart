import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

const MethodChannel _channel =
    MethodChannel('dev.digitalcredentials.flutter_wallet/issuance');

/// Preview of the credential an issuer is offering.
class IssuanceOffer {
  const IssuanceOffer({
    required this.id,
    required this.title,
    required this.docType,
    required this.claims,
    this.subtitle,
  });

  final String id;
  final String title;
  final String? subtitle;
  final String docType;
  final List<({String displayName, String? value})> claims;

  factory IssuanceOffer.fromMap(Map<Object?, Object?> map) => IssuanceOffer(
        id: map['id']! as String,
        title: map['title']! as String,
        subtitle: map['subtitle'] as String?,
        docType: map['docType']! as String,
        claims: (map['claims']! as List<Object?>)
            .cast<Map<Object?, Object?>>()
            .map((c) => (
                  displayName: c['displayName']! as String,
                  value: c['value'] as String?,
                ))
            .toList(growable: false),
      );
}

/// The route the issuance activity opens.
///
/// By the time this is shown the credential has already been fetched from the
/// issuer and checked, but nothing has been stored — Confirm commits it,
/// Cancel discards it. Doing the work before asking is what lets the sheet
/// show the user what they are actually accepting.
class IssuanceSheet extends StatefulWidget {
  const IssuanceSheet({super.key});

  /// The route the credential-provider activity starts its engine on. A host
  /// must make this resolve to [IssuanceSheet], or issuance silently hangs.
  static const String route = '/create';

  @override
  State<IssuanceSheet> createState() => _IssuanceSheetState();
}

class _IssuanceSheetState extends State<IssuanceSheet> {
  IssuanceOffer? _offer;
  String? _error;
  bool _working = true;

  @override
  void initState() {
    super.initState();
    _start();
  }

  Future<void> _start() async {
    try {
      final result = await _channel.invokeMethod<Map<Object?, Object?>>('start');
      if (!mounted) return;
      setState(() {
        _offer = result == null ? null : IssuanceOffer.fromMap(result);
        _working = false;
      });
    } on PlatformException catch (e) {
      if (!mounted) return;
      setState(() {
        _error = e.message ?? e.code;
        _working = false;
      });
    }
  }

  Future<void> _confirm() async {
    setState(() => _working = true);
    try {
      await _channel.invokeMethod<String>('confirm');
    } on PlatformException catch (e) {
      if (!mounted) return;
      setState(() {
        _error = e.message ?? e.code;
        _working = false;
      });
    }
  }

  Future<void> _cancel() => _channel.invokeMethod<void>('cancel');

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      backgroundColor: Colors.transparent,
      body: Align(
        alignment: Alignment.bottomCenter,
        child: Material(
          color: theme.colorScheme.surface,
          borderRadius: const BorderRadius.vertical(top: Radius.circular(24)),
          child: SafeArea(
            top: false,
            child: Padding(
              padding: const EdgeInsets.fromLTRB(20, 12, 20, 16),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: _body(theme),
              ),
            ),
          ),
        ),
      ),
    );
  }

  List<Widget> _body(ThemeData theme) {
    final grabber = Center(
      child: Container(
        width: 36,
        height: 4,
        margin: const EdgeInsets.only(bottom: 16),
        decoration: BoxDecoration(
          color: theme.colorScheme.outlineVariant,
          borderRadius: BorderRadius.circular(2),
        ),
      ),
    );

    if (_working && _offer == null && _error == null) {
      return [
        grabber,
        Text('Getting your credential', style: theme.textTheme.titleMedium),
        const SizedBox(height: 16),
        const LinearProgressIndicator(),
        const SizedBox(height: 12),
      ];
    }

    if (_error != null) {
      return [
        grabber,
        Text('Could not add the credential', style: theme.textTheme.titleMedium),
        const SizedBox(height: 8),
        Text(_error!, style: theme.textTheme.bodySmall),
        const SizedBox(height: 16),
        Align(
          alignment: Alignment.centerRight,
          child: TextButton(onPressed: _cancel, child: const Text('Close')),
        ),
      ];
    }

    final offer = _offer!;
    return [
      grabber,
      Text('Add to your wallet', style: theme.textTheme.titleMedium),
      const SizedBox(height: 12),
      Text(offer.title, style: theme.textTheme.titleLarge),
      if (offer.subtitle != null)
        Text(offer.subtitle!, style: theme.textTheme.bodyMedium),
      const SizedBox(height: 12),
      ConstrainedBox(
        constraints: const BoxConstraints(maxHeight: 220),
        child: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              for (final claim in offer.claims)
                Padding(
                  padding: const EdgeInsets.symmetric(vertical: 2),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Expanded(flex: 2, child: Text(claim.displayName)),
                      Expanded(
                        flex: 3,
                        child: Text(
                          claim.value ?? '—',
                          style: theme.textTheme.bodySmall,
                        ),
                      ),
                    ],
                  ),
                ),
            ],
          ),
        ),
      ),
      const SizedBox(height: 16),
      Row(
        mainAxisAlignment: MainAxisAlignment.end,
        children: [
          TextButton(
            onPressed: _working ? null : _cancel,
            child: const Text('Cancel'),
          ),
          const SizedBox(width: 8),
          FilledButton(
            onPressed: _working ? null : _confirm,
            child: const Text('Add'),
          ),
        ],
      ),
    ];
  }
}

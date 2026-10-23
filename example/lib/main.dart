import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show rootBundle;
import 'package:flutter_wallet/flutter_wallet.dart';

/// Stands in for the app this plugin will eventually be embedded in: it loads
/// a test credential, registers the wallet, and lists what is held.
void main() => runApp(const WalletExampleApp());

class WalletExampleApp extends StatelessWidget {
  const WalletExampleApp({super.key});

  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'Wallet',
        theme: ThemeData(colorSchemeSeed: Colors.indigo, useMaterial3: true),
        // The issuance activity starts the engine on '/create'; the launcher
        // activity starts on '/'. One Dart entrypoint, two entry routes.
        initialRoute: '/',
        routes: {
          '/': (_) => const CredentialListScreen(),
          '/create': (_) => const IssuanceSheet(),
        },
      );
}

class CredentialListScreen extends StatefulWidget {
  const CredentialListScreen({super.key});

  @override
  State<CredentialListScreen> createState() => _CredentialListScreenState();
}

class _CredentialListScreenState extends State<CredentialListScreen>
    with WidgetsBindingObserver {
  final _wallet = FlutterWallet.instance;

  List<WalletCredential> _credentials = const [];
  String _status = 'starting...';
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _startUp();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    // Issuance happens in a separate activity, so the list can go stale while
    // we are backgrounded. Cheaper than an event channel, and good enough.
    if (state == AppLifecycleState.resumed) _refresh();
  }

  Future<void> _startUp() async {
    await _run('registering', () async {
      final existing = await _wallet.listCredentials();
      if (existing.isEmpty) {
        final json = await rootBundle.loadString('assets/credentials.json');
        await _wallet.addCredentials(json);
      }
      final count = await _wallet.register();
      return 'registered $count credential(s)';
    });
    await _refresh();
  }

  Future<void> _refresh() async {
    final list = await _wallet.listCredentials();
    if (mounted) setState(() => _credentials = list);
  }

  Future<void> _run(String what, Future<String> Function() action) async {
    setState(() {
      _busy = true;
      _status = '$what...';
    });
    try {
      final message = await action();
      if (mounted) setState(() => _status = message);
    } catch (e) {
      if (mounted) setState(() => _status = '$what failed: $e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _reload() async {
    await _run('reloading', () async {
      final json = await rootBundle.loadString('assets/credentials.json');
      final ids = await _wallet.addCredentials(json);
      final count = await _wallet.register();
      return 'loaded ${ids.length}, registered $count';
    });
    await _refresh();
  }

  Future<void> _delete(WalletCredential credential) async {
    await _run('deleting', () async {
      await _wallet.deleteCredential(credential.id);
      final count = await _wallet.register();
      return 'deleted ${credential.title}, $count left';
    });
    await _refresh();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Wallet'),
        actions: [
          IconButton(
            onPressed: _busy ? null : _reload,
            icon: const Icon(Icons.refresh),
            tooltip: 'Reload test credentials',
          ),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(28),
          child: Padding(
            padding: const EdgeInsets.only(left: 16, right: 16, bottom: 8),
            child: Align(
              alignment: Alignment.centerLeft,
              child: Text(
                _status,
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ),
          ),
        ),
      ),
      body: _credentials.isEmpty
          ? const Center(child: Text('No credentials'))
          : ListView.builder(
              itemCount: _credentials.length,
              itemBuilder: (context, i) => _CredentialCard(
                credential: _credentials[i],
                onDelete: _busy ? null : () => _delete(_credentials[i]),
              ),
            ),
    );
  }
}

class _CredentialCard extends StatelessWidget {
  const _CredentialCard({required this.credential, this.onDelete});

  final WalletCredential credential;
  final VoidCallback? onDelete;

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      child: ExpansionTile(
        title: Text(credential.title),
        subtitle: Text(credential.subtitle ?? credential.docType),
        trailing: IconButton(
          onPressed: onDelete,
          icon: const Icon(Icons.delete_outline),
          tooltip: 'Delete',
        ),
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(credential.docType,
                    style: Theme.of(context).textTheme.labelSmall),
                const SizedBox(height: 8),
                for (final claim in credential.claims)
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
                            style: const TextStyle(
                                fontFamily: 'monospace', fontSize: 12),
                          ),
                        ),
                      ],
                    ),
                  ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

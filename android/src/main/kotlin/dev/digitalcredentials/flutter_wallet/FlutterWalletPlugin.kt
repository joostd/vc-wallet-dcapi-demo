package dev.digitalcredentials.flutter_wallet

import android.content.Context
import android.util.Log
import dev.digitalcredentials.flutter_wallet.data.CredentialConfigurationMDoc
import dev.digitalcredentials.flutter_wallet.data.CredentialStore
import dev.digitalcredentials.flutter_wallet.data.displayNameFor
import dev.digitalcredentials.flutter_wallet.data.IssuanceRegistry
import dev.digitalcredentials.flutter_wallet.data.RegistryBuilder
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val TAG = "FlutterWallet"
private const val CHANNEL = "dev.digitalcredentials.flutter_wallet/wallet"

/**
 * The host-facing surface of the wallet.
 *
 * Deliberately small. Nothing about CBOR, COSE, keys or protocol messages
 * crosses this boundary — the host gets a list to render and a way to add and
 * remove credentials. Everything durable stays on this side, because the
 * registry needs typed entries and signing needs a KeyStore handle, neither
 * of which can travel over a channel.
 */
class FlutterWalletPlugin : FlutterPlugin, MethodChannel.MethodCallHandler {

    private lateinit var channel: MethodChannel
    private lateinit var context: Context
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    private val store: CredentialStore by lazy { walletStore(context) }

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        context = binding.applicationContext
        channel = MethodChannel(binding.binaryMessenger, CHANNEL)
        channel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "register" -> launchCatching(result) {
                RegistryBuilder.register(context, store.credentials.value)
                // Also advertise that this wallet can receive credentials.
                // Separate registry, separate matcher: there is no typed API
                // for creation options yet.
                IssuanceRegistry.register(
                    context,
                    title = call.argument<String>("title") ?: "Wallet",
                    subtitle = call.argument<String>("subtitle")
                        ?: "Save your document to this wallet",
                )
                store.credentials.value.size
            }

            "listCredentials" -> launchCatching(result) { projection() }

            "addCredentials" -> {
                val json = call.argument<String>("json")
                if (json == null) {
                    result.error("bad_args", "addCredentials needs a `json` string", null)
                    return
                }
                launchCatching(result) {
                    val items = withContext(Dispatchers.IO) { store.parse(json) }
                    store.putAll(items)
                    RegistryBuilder.register(context, store.credentials.value)
                    items.map { it.id }
                }
            }

            "deleteCredential" -> {
                val id = call.argument<String>("id")
                if (id == null) {
                    result.error("bad_args", "deleteCredential needs an `id`", null)
                    return
                }
                launchCatching(result) {
                    store.remove(id)
                    RegistryBuilder.register(context, store.credentials.value)
                    null
                }
            }

            else -> result.notImplemented()
        }
    }

    /**
     * A projection of each credential: enough to render, nothing sensitive.
     * Claim values come from the mdoc itself rather than the stored JSON,
     * which is also what the registry entries are built from — so what the
     * host shows and what the system picker shows cannot drift apart.
     */
    private fun projection(): List<Map<String, Any?>> =
        store.credentials.value.mapNotNull { item ->
            val config = item.config as? CredentialConfigurationMDoc ?: return@mapNotNull null
            mapOf(
                "id" to item.id,
                "title" to item.displayData.title,
                "subtitle" to item.displayData.subtitle,
                "docType" to config.doctype,
                "claims" to item.credentials.first().mdoc.issuerSignedNamespaces
                    .flatMap { (namespace, elements) ->
                        elements.map { (element, value) ->
                            mapOf(
                                "namespace" to namespace,
                                "identifier" to element,
                                "displayName" to config.displayNameFor(namespace, element),
                                "value" to value?.toString(),
                            )
                        }
                    },
            )
        }

    private fun launchCatching(result: MethodChannel.Result, block: suspend () -> Any?) {
        scope.launch {
            try {
                result.success(block())
            } catch (e: Exception) {
                Log.e(TAG, "${e.javaClass.simpleName} in ${'$'}{javaClass.simpleName}", e)
                result.error(e.javaClass.simpleName, e.message, null)
            }
        }
    }

    companion object {
        private var storeInstance: CredentialStore? = null

        /**
         * One store per process. The provider activities run in the host
         * process but outside the Flutter engine, so they need the same
         * instance without going through the plugin binding.
         */
        @Synchronized
        fun walletStore(context: Context): CredentialStore =
            storeInstance ?: CredentialStore(context.applicationContext)
                .also { storeInstance = it }
    }
}

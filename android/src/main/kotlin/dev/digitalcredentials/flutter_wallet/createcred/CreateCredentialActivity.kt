package dev.digitalcredentials.flutter_wallet.createcred

import android.content.Intent
import android.util.Log
import androidx.credentials.CreateCredentialResponse
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.CreateDigitalCredentialResponse
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import dev.digitalcredentials.flutter_wallet.FlutterWalletPlugin
import dev.digitalcredentials.flutter_wallet.data.Credential
import dev.digitalcredentials.flutter_wallet.data.CredentialConfigurationMDoc
import dev.digitalcredentials.flutter_wallet.data.CredentialDisplayData
import dev.digitalcredentials.flutter_wallet.data.CredentialItem
import dev.digitalcredentials.flutter_wallet.data.CredentialKeyHardware
import dev.digitalcredentials.flutter_wallet.data.displayNameFor
import dev.digitalcredentials.flutter_wallet.data.RegistryBuilder
import dev.digitalcredentials.flutter_wallet.decodeBase64UrlNoPadding
import dev.digitalcredentials.flutter_wallet.mdoc.MDoc
import dev.digitalcredentials.flutter_wallet.openid4vci.OpenId4VCI
import dev.digitalcredentials.flutter_wallet.toBase64UrlNoPadding
import dev.digitalcredentials.flutter_wallet.toFixedByteArray
import io.flutter.embedding.android.FlutterActivityLaunchConfigs.BackgroundMode
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.security.interfaces.ECPublicKey
import java.util.UUID

private const val TAG = "FlutterWallet"
private const val CHANNEL = "dev.digitalcredentials.flutter_wallet/issuance"

/**
 * Receives a credential, with a Flutter sheet for consent.
 *
 * This is the one activity where the wallet draws its own UI, so it is the
 * one hosted by Flutter. FlutterFragmentActivity, not FlutterActivity: the
 * latter extends bare Activity.
 *
 * No engine caching. A cached engine warmed in the host's Application would
 * pay engine start on the presentation path too — which uses no Flutter at
 * all — and would leak Navigator state between invocations. The cost lands
 * here instead, right after the user has deliberately tapped "Add".
 */
@OptIn(ExperimentalDigitalCredentialApi::class)
class CreateCredentialActivity : FlutterFragmentActivity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var pending: CredentialItem? = null

    /** The system's intent carries no route extra, so say where to start. */
    override fun getInitialRoute(): String = "/create"

    override fun getBackgroundMode(): BackgroundMode = BackgroundMode.transparent

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    // Dart initiates every call. With a per-activity engine
                    // there is no guarantee Dart has registered its handler
                    // when onCreate runs, so Kotlin never calls into Dart.
                    "start" -> scope.launch { start(result) }
                    "confirm" -> scope.launch { confirm(result) }
                    "cancel" -> { cancel(); result.success(null) }
                    else -> result.notImplemented()
                }
            }
    }

    /** Runs the whole issuance and returns a preview for the sheet. */
    private suspend fun start(result: MethodChannel.Result) {
        try {
            val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
                ?: throw IllegalStateException("launched without a create request")
            // Read straight off the base request: the concrete type varies
            // (and will eventually be a structured Jetpack property), but
            // credentialData is always there.
            val requestJson = request.callingRequest.credentialData
                .getString("androidx.credentials.BUNDLE_KEY_REQUEST_JSON")
                ?: throw IllegalStateException("no request json in credentialData")

            val entry = JSONObject(requestJson).getJSONArray("requests").getJSONObject(0)
            val protocol = entry.getString("protocol")
            require(protocol in SUPPORTED_PROTOCOLS) {
                "unsupported issuance protocol \"$protocol\""
            }
            Log.i(TAG, "issuance request, protocol=$protocol")

            val item = withContext(Dispatchers.IO) { issue(entry.getJSONObject("data").toString()) }
            pending = item

            val config = item.config as CredentialConfigurationMDoc
            result.success(
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
            )
        } catch (e: Exception) {
            Log.e(TAG, "issuance failed", e)
            result.error(e.javaClass.simpleName, e.message, null)
        }
    }

    /** token -> nonce -> attestation proof -> credential. */
    private suspend fun issue(offerJson: String): CredentialItem {
        val vci = OpenId4VCI(offerJson)
        val token = vci.requestToken()
        val nonce = vci.requestNonce()
        val proof = vci.createAttestationProof(nonce)
        val response = vci.requestCredential(token.accessToken, proof)

        val issued = response.credentials?.firstOrNull()
            ?: throw IllegalStateException("issuer returned no credential")
        val config = vci.offer.issuerMetadata
            .credentialConfigurationsSupported[vci.configurationId]
            ?: throw IllegalStateException("offer has no configuration ${vci.configurationId}")

        // The MSO must be bound to the key we just proved. If it is not, the
        // credential is useless and every later presentation fails with an
        // opaque "device signature invalid" — so check it here, where the
        // cause is still obvious.
        val mdoc = MDoc(issued.credential.decodeBase64UrlNoPadding())
        val public = proof.publicKey as ECPublicKey
        val expectedX = String(public.w.affineX.toFixedByteArray(32))
        val expectedY = String(public.w.affineY.toFixedByteArray(32))
        check(mdoc.deviceKey.first == expectedX && mdoc.deviceKey.second == expectedY) {
            "issued credential is bound to a different key than the one we proved"
        }

        val display = response.display?.firstOrNull()
        return CredentialItem(
            id = UUID.randomUUID().toString().replace("-", ""),
            config = config,
            displayData = CredentialDisplayData(
                title = display?.name ?: "Credential",
                subtitle = display?.description,
            ),
            credentials = listOf(
                Credential(
                    key = CredentialKeyHardware(
                        publicKey = public.encoded.toBase64UrlNoPadding(),
                        keyAlias = proof.keyAlias,
                    ),
                    credential = issued.credential,
                )
            ),
        )
    }

    private suspend fun confirm(result: MethodChannel.Result) {
        val item = pending
        if (item == null) {
            result.error("no_pending", "nothing to confirm", null)
            return
        }
        try {
            val store = FlutterWalletPlugin.walletStore(applicationContext)
            store.put(item)
            RegistryBuilder.register(applicationContext, store.credentials.value)

            val resultData = Intent()
            PendingIntentHandler.setCreateCredentialResponse(resultData, ackResponse())
            setResult(RESULT_OK, resultData)
            result.success(item.id)
            finish()
        } catch (e: Exception) {
            Log.e(TAG, "could not store the credential", e)
            result.error(e.javaClass.simpleName, e.message, null)
        }
    }

    private fun cancel() {
        val resultData = Intent()
        PendingIntentHandler.setCreateCredentialException(
            resultData,
            CreateCredentialUnknownException("cancelled"),
        )
        setResult(RESULT_OK, resultData)
        finish()
    }

    /**
     * The ack the browser receives. It carries no credential — that went
     * straight from the issuer to us over HTTP.
     */
    private fun ackResponse(): CreateCredentialResponse =
        CreateDigitalCredentialResponse(
            JSONObject()
                .put("protocol", "openid4vci")
                .put("data", JSONObject())
                .toString()
        )

    companion object {
        /**
         * The issuance matcher only contains these two; plain "openid4vci"
         * never reaches a wallet at all.
         */
        val SUPPORTED_PROTOCOLS = setOf("openid4vci1.0", "openid4vci-v1")
    }
}

package dev.digitalcredentials.flutter_wallet.getcred

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.GetCredentialResponse
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderGetCredentialRequest
import androidx.credentials.registry.provider.selectedCredentialSet
import androidx.credentials.registry.provider.selectedEntryId
import androidx.credentials.GetDigitalCredentialOption
import androidx.fragment.app.FragmentActivity
import dev.digitalcredentials.flutter_wallet.FlutterWalletPlugin
import dev.digitalcredentials.flutter_wallet.data.CredentialConfigurationMDoc
import dev.digitalcredentials.flutter_wallet.data.CredentialItem
import dev.digitalcredentials.flutter_wallet.data.toPrivateKey
import dev.digitalcredentials.flutter_wallet.decodeBase64UrlNoPadding
import dev.digitalcredentials.flutter_wallet.mdoc.MDoc
import dev.digitalcredentials.flutter_wallet.mdoc.createSessionTranscript
import dev.digitalcredentials.flutter_wallet.mdoc.filterIssuerSigned
import dev.digitalcredentials.flutter_wallet.mdoc.generateDeviceResponse
import dev.digitalcredentials.flutter_wallet.mdoc.webOriginOrAppOrigin
import dev.digitalcredentials.flutter_wallet.openid4vp.OpenId4VP
import dev.digitalcredentials.flutter_wallet.openid4vp.OpenId4VPMatchedCredential
import dev.digitalcredentials.flutter_wallet.openid4vp.OpenId4VPMatchedMDocClaims
import dev.digitalcredentials.flutter_wallet.toBase64UrlNoPadding
import org.json.JSONArray
import org.json.JSONObject

private const val TAG = "FlutterWallet"

/**
 * Answers a Digital Credentials presentation request.
 *
 * Draws no UI of its own: by the time the system launches this, the user has
 * already chosen a credential in the Play services picker, which was built
 * from the registry. All that is left is to build the response, confirm with
 * a biometric, and hand it back. That is why this is a plain FragmentActivity
 * — Flutter would only add an engine start on the most latency-sensitive path
 * in the wallet, to render nothing.
 *
 * FragmentActivity rather than Activity because BiometricPrompt requires one.
 */
@OptIn(ExperimentalDigitalCredentialApi::class)
class GetCredentialActivity : FragmentActivity() {

    private var request: ProviderGetCredentialRequest? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        if (request == null) {
            Log.w(TAG, "launched without a provider request; nothing to do")
            finish()
            return
        }
        this.request = request
        Log.i(TAG, "selectedEntryId=${request.selectedEntryId}")
        handleRequest(request)
    }

    private fun handleRequest(request: ProviderGetCredentialRequest) {
        var origin = request.callingAppInfo.getOrigin(privilegedApps())
        // Chrome reports https origins with the default port attached; the
        // verifier computing the session transcript will not.
        if (origin != null && origin.endsWith(":443")) {
            origin = origin.substringBefore(":443")
        }
        Log.i(TAG, "origin=$origin")

        val option = request.credentialOptions
            .filterIsInstance<GetDigitalCredentialOption>()
            .firstOrNull()
        if (option == null) {
            Log.w(TAG, "no digital credential option in the request")
            finish()
            return
        }

        val resultData = Intent()
        try {
            val selection = if (request.selectedEntryId != null) {
                InternalSelectionInfo.fromEntryIdJson(request.selectedEntryId!!)
            } else {
                InternalSelectionInfo.fromSelectedSet(request.selectedCredentialSet!!)
            }

            val response = buildResponse(
                requestJson = option.requestJson,
                selection = selection,
                origin = webOriginOrAppOrigin(
                    origin,
                    request.callingAppInfo.signingInfoCompat
                        .signingCertificateHistory[0].toByteArray(),
                ),
            )
            authenticateThenReturn(resultData, response)
        } catch (e: Exception) {
            Log.e(TAG, "failed to build a response", e)
            fail(resultData)
        }
    }

    private fun authenticateThenReturn(resultData: Intent, response: String) {
        val prompt = BiometricPrompt(
            this,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult,
                ) {
                    PendingIntentHandler.setGetCredentialResponse(
                        resultData,
                        GetCredentialResponse(DigitalCredential(response)),
                    )
                    // Always RESULT_OK: failure is signalled by the exception
                    // extra, not by the result code.
                    setResult(RESULT_OK, resultData)
                    finish()
                }

                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    Log.e(TAG, "biometric error $code: $message")
                    fail(resultData)
                }
            },
        )
        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("Verify your identity")
                .setConfirmationRequired(false)
                .setStrongOrDeviceAuthenticators(this)
                .build()
        )
    }

    private fun fail(resultData: Intent) {
        PendingIntentHandler.setGetCredentialException(
            resultData,
            GetCredentialUnknownException(),
        )
        setResult(RESULT_OK, resultData)
        finish()
    }

    /** Builds the `{protocol, data}` response for the selected credential(s). */
    private fun buildResponse(
        requestJson: String,
        selection: InternalSelectionInfo,
        origin: String,
    ): String {
        val options = DigitalCredentialRequestOptions.createFrom(requestJson)
        val protocol = options.protocolAt(selection.requestIdx)
        val data = options.dataAt(selection.requestIdx)
        Log.i(TAG, "protocol=$protocol")

        require(protocol in OpenId4VP.IDENTIFIERS) {
            "unsupported protocol \"$protocol\"; this wallet implements " +
                OpenId4VP.IDENTIFIERS.joinToString()
        }

        val openId4VP = OpenId4VP(data, computeClientId(request!!.callingAppInfo), protocol)
        val store = FlutterWalletPlugin.walletStore(applicationContext)

        val vpToken = JSONObject()
        for (cred in selection.creds) {
            val selected = store.get(cred.entryId)
                ?: throw IllegalStateException("selected credential \"${cred.entryId}\" not found")
            val config = selected.config as? CredentialConfigurationMDoc
                ?: throw UnsupportedOperationException(
                    "unsupported format ${selected.config.format}"
                )

            val matched = matchClaims(openId4VP, selected, cred)
            val claimSets = (matched.matchedClaims as OpenId4VPMatchedMDocClaims).claimSets

            val deviceResponse = generateDeviceResponse(
                doctype = config.doctype,
                issuerSigned = filterIssuerSigned(
                    selected.credentials.first().credential.decodeBase64UrlNoPadding(),
                    claimSets,
                ),
                devicePrivateKey = selected.credentials.first().key.toPrivateKey(),
                sessionTranscript = createSessionTranscript(openId4VP.getHandover(origin)),
                deviceNamespaces = emptyMap(),
            )
            vpToken.put(
                matched.dcqlId,
                JSONArray().put(deviceResponse.toBase64UrlNoPadding()),
            )
        }

        return JSONObject()
            .put("protocol", protocol)
            .put("data", JSONObject(openId4VP.generateResponse(vpToken)))
            .toString()
    }

    /**
     * Which claims to disclose.
     *
     * The matcher usually tells us, in the selection metadata. When it does
     * not, fall back to running the DCQL query ourselves — otherwise we would
     * disclose everything, which is the wrong default for a wallet.
     */
    private fun matchClaims(
        openId4VP: OpenId4VP,
        selected: CredentialItem,
        cred: SelectedCred,
    ): OpenId4VPMatchedCredential {
        val paths = cred.matchedClaimPaths
            ?: return openId4VP.performQueryOnCredential(selected, cred.dcqlId)

        val byNamespace = mutableMapOf<String, MutableList<String>>()
        for (i in 0 until paths.paths.length()) {
            val path = paths.paths.getJSONArray(i)
            byNamespace.getOrPut(path.getString(0)) { mutableListOf() }.add(path.getString(1))
        }
        return OpenId4VPMatchedCredential(
            cred.dcqlId,
            OpenId4VPMatchedMDocClaims(listOf(byNamespace)),
        )
    }

    private fun computeClientId(callingAppInfo: CallingAppInfo): String {
        val origin = callingAppInfo.getOrigin(privilegedApps())
        return if (origin == null) {
            "android-origin:${callingAppInfo.packageName}"
        } else {
            "web-origin:$origin"
        }
    }

    /**
     * The privileged-browser allowlist, shipped with the plugin.
     *
     * Load-bearing: getOrigin() only returns a web origin for an allowlisted
     * caller, and that origin is hashed into the session transcript. Without
     * it a Chrome request yields an android-origin and every verifier rejects
     * the device signature. The list also covers Play services, which is the
     * caller on the cross-device path.
     */
    private fun privilegedApps(): String =
        assets.open("apps.json").bufferedReader().use { it.readText() }

    // -- request shapes ----------------------------------------------------

    sealed class DigitalCredentialRequestOptions {
        abstract fun protocolAt(index: Int): String
        abstract fun dataAt(index: Int): JSONObject

        data class Modern(val requests: List<Pair<String, JSONObject>>) :
            DigitalCredentialRequestOptions() {
            override fun protocolAt(index: Int) = requests[index].first
            override fun dataAt(index: Int) = requests[index].second
        }

        /** Older Chrome sends `providers` with the request as a JSON string. */
        data class Legacy(val providers: List<Pair<String, String>>) :
            DigitalCredentialRequestOptions() {
            override fun protocolAt(index: Int) = providers[index].first
            override fun dataAt(index: Int) = JSONObject(providers[index].second)
        }

        companion object {
            fun createFrom(request: String): DigitalCredentialRequestOptions {
                val json = JSONObject(request)
                if (json.has("requests")) {
                    val array = json.getJSONArray("requests")
                    return Modern(
                        (0 until array.length()).map { i ->
                            val entry = array.getJSONObject(i)
                            val data = entry.get("data")
                            entry.getString("protocol") to
                                if (data is String) JSONObject(data) else data as JSONObject
                        }
                    )
                }
                val array = json.getJSONArray("providers")
                return Legacy(
                    (0 until array.length()).map { i ->
                        val entry = array.getJSONObject(i)
                        entry.getString("protocol") to entry.getString("request")
                    }
                )
            }
        }
    }
}

/**
 * Strong biometrics when enrolled, otherwise the device credential.
 *
 * The API 28-29 branch is not optional at minSdk 28: BiometricPrompt rejects
 * BIOMETRIC_STRONG or DEVICE_CREDENTIAL there, and setDeviceCredentialAllowed
 * must not be combined with a negative button.
 */
fun BiometricPrompt.PromptInfo.Builder.setStrongOrDeviceAuthenticators(
    context: Context,
): BiometricPrompt.PromptInfo.Builder {
    val strong = BiometricManager.Authenticators.BIOMETRIC_STRONG
    val manager = BiometricManager.from(context)
    if (manager.canAuthenticate(strong) == BiometricManager.BIOMETRIC_SUCCESS) {
        setAllowedAuthenticators(strong).setNegativeButtonText("Cancel")
    } else if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
        @Suppress("DEPRECATION")
        setDeviceCredentialAllowed(true)
    } else {
        setAllowedAuthenticators(
            strong or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )
    }
    return this
}

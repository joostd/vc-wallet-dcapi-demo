package dev.digitalcredentials.flutter_wallet.openid4vp

import dev.digitalcredentials.flutter_wallet.cbor.cborEncode
import dev.digitalcredentials.flutter_wallet.data.CredentialItem
import org.json.JSONObject
import java.security.MessageDigest

/**
 * An OpenID4VP 1.0 authorization request, and the response to it.
 *
 * Trimmed from CMWallet's version to the unsigned, unencrypted case:
 *
 *  - only `openid4vp-v1-unsigned`. Signed and multisigned requests need JWS
 *    verification, which was dropped along with the jose4j dependency.
 *  - only `response_mode: dc_api`. The `dc_api.jwt` branch encrypts the
 *    response as a JWE, which went with the same cut.
 *  - no `transaction_data`. That is the payments flow.
 *  - no draft-24 identifier. Nothing in the current stack parses it.
 *
 * Each of those is a localized add-back: the handover and response shapes
 * for them are in CMWallet's OpenId4VP.kt if they are ever needed.
 */
class OpenId4VP(
    val requestJson: JSONObject,
    val clientId: String,
    val protocolIdentifier: String = IDENTIFIER_1_0_UNSIGNED,
) {
    val nonce: String
    val dcqlQuery: JSONObject
    val responseMode: String?

    init {
        require(protocolIdentifier in IDENTIFIERS) {
            "unsupported protocol identifier: $protocolIdentifier"
        }
        require(requestJson.has("nonce")) { "request must contain a nonce" }
        require(requestJson.has("dcql_query")) { "request must contain a dcql_query" }

        nonce = requestJson.getString("nonce")
        dcqlQuery = requestJson.getJSONObject("dcql_query")
        responseMode = requestJson.optString("response_mode")

        require(responseMode == RESPONSE_MODE_DC_API) {
            "only response_mode \"$RESPONSE_MODE_DC_API\" is supported, got \"$responseMode\". " +
                "Encrypted responses (dc_api.jwt) were deliberately left out."
        }
    }

    fun matchCredentials(credentialStore: JSONObject): Map<String, List<MatchedCredential>> =
        DCQLQuery(dcqlQuery, credentialStore)

    fun getDcqlCredentialObject(dcqlId: String): JSONObject? =
        getDqclCredentialById(dcqlQuery, dcqlId)

    fun performQueryOnCredential(
        selectedCredential: CredentialItem,
        dcqlCredId: String? = null,
    ): OpenId4VPMatchedCredential =
        performQueryOnCredential(dcqlQuery, selectedCredential, dcqlCredId)

    /**
     * The OpenID4VPDCAPIHandover that binds the response to this request.
     *
     * `["OpenID4VPDCAPIHandover", SHA-256(cbor([origin, nonce, null]))]`
     *
     * The third element of the handover info is the encryption key
     * thumbprint, and is null precisely because the response is unencrypted.
     * This is what the verifier recomputes; if it disagrees by one byte the
     * device signature fails and says nothing about why.
     */
    fun getHandover(origin: String): List<Any> {
        val handoverInfo = listOf(origin, nonce, null)
        return listOf(
            HANDOVER_IDENTIFIER,
            MessageDigest.getInstance("SHA-256").digest(cborEncode(handoverInfo)),
        )
    }

    fun generateResponse(vpToken: JSONObject): String =
        JSONObject().put("vp_token", vpToken).toString()

    companion object {
        const val IDENTIFIER_1_0_UNSIGNED = "openid4vp-v1-unsigned"
        const val RESPONSE_MODE_DC_API = "dc_api"
        const val HANDOVER_IDENTIFIER = "OpenID4VPDCAPIHandover"

        val IDENTIFIERS = setOf(IDENTIFIER_1_0_UNSIGNED)
    }
}

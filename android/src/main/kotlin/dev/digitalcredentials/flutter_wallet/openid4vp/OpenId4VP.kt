package dev.digitalcredentials.flutter_wallet.openid4vp

import dev.digitalcredentials.flutter_wallet.cbor.cborEncode
import dev.digitalcredentials.flutter_wallet.data.CredentialItem
import org.json.JSONObject
import java.security.MessageDigest

/**
 * An OpenID4VP 1.0 authorization request, and the response to it.
 *
 * Trimmed from CMWallet's version to the unsigned case:
 *
 *  - only `openid4vp-v1-unsigned`. Signed and multisigned requests need JWS
 *    verification, which was dropped along with the jose4j dependency.
 *  - no `transaction_data`. That is the payments flow.
 *  - no draft-24 identifier. Nothing in the current stack parses it.
 *
 * Both response modes are implemented. `dc_api` returns the `vp_token` as
 * JSON; `dc_api.jwt` encrypts it to the verifier's key (see [jweCompact]),
 * which HAIP 1.0 requires and the EUDI verifiers therefore always ask for.
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

    /** The verifier's key, and the algorithm to use. Null unless `dc_api.jwt`. */
    val encryptionKey: ResponseEncryptionKey?
    val responseEnc: String?

    init {
        require(protocolIdentifier in IDENTIFIERS) {
            "unsupported protocol identifier: $protocolIdentifier"
        }
        require(requestJson.has("nonce")) { "request must contain a nonce" }
        require(requestJson.has("dcql_query")) { "request must contain a dcql_query" }

        nonce = requestJson.getString("nonce")
        dcqlQuery = requestJson.getJSONObject("dcql_query")
        responseMode = requestJson.optString("response_mode")

        require(responseMode == RESPONSE_MODE_DC_API || responseMode == RESPONSE_MODE_DC_API_JWT) {
            "unsupported response_mode \"$responseMode\"; this wallet implements " +
                "\"$RESPONSE_MODE_DC_API\" and \"$RESPONSE_MODE_DC_API_JWT\""
        }

        if (responseMode == RESPONSE_MODE_DC_API_JWT) {
            val clientMetadata = requestJson.optJSONObject("client_metadata")
                ?: throw IllegalArgumentException(
                    "response_mode \"$RESPONSE_MODE_DC_API_JWT\" needs client_metadata " +
                        "with the key to encrypt to"
                )
            encryptionKey = encryptionKeyOf(clientMetadata)
            responseEnc = responseEncOf(clientMetadata)
        } else {
            encryptionKey = null
            responseEnc = null
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
     * The third element of the handover info is the thumbprint of the key the
     * response is encrypted to, and null when it is not encrypted. This is
     * what the verifier recomputes; if it disagrees by one byte the device
     * signature fails and says nothing about why.
     */
    fun getHandover(origin: String): List<Any> {
        val handoverInfo = listOf(origin, nonce, encryptionKey?.let { jwkThumbprintSha256(it) })
        return listOf(
            HANDOVER_IDENTIFIER,
            MessageDigest.getInstance("SHA-256").digest(cborEncode(handoverInfo)),
        )
    }

    fun generateResponse(vpToken: JSONObject): String {
        val payload = JSONObject().put("vp_token", vpToken).toString()
        val key = encryptionKey ?: return payload
        return JSONObject()
            .put("response", jweCompact(key, responseEnc!!, payload))
            .toString()
    }

    companion object {
        const val IDENTIFIER_1_0_UNSIGNED = "openid4vp-v1-unsigned"
        const val RESPONSE_MODE_DC_API = "dc_api"
        const val RESPONSE_MODE_DC_API_JWT = "dc_api.jwt"
        const val HANDOVER_IDENTIFIER = "OpenID4VPDCAPIHandover"

        val IDENTIFIERS = setOf(IDENTIFIER_1_0_UNSIGNED)

        /** Content encryption algorithms, most preferred first. */
        private val SUPPORTED_ENC = listOf("A128GCM", "A256GCM")

        /**
         * The verifier's response encryption key.
         *
         * A verifier may advertise several keys — signing as well as
         * encryption — so take the first that can actually be used: an EC key
         * on P-256 that is not marked for signing.
         */
        private fun encryptionKeyOf(clientMetadata: JSONObject): ResponseEncryptionKey {
            val keys = clientMetadata.optJSONObject("jwks")?.optJSONArray("keys")
                ?: throw IllegalArgumentException("client_metadata carries no jwks.keys")
            for (i in 0 until keys.length()) {
                val jwk = keys.optJSONObject(i) ?: continue
                if (jwk.optString("kty") != "EC" || jwk.optString("crv") != "P-256") continue
                if (jwk.optString("use", "enc") != "enc") continue
                val alg = jwk.optString("alg")
                if (alg.isNotEmpty() && alg != "ECDH-ES") continue
                return ResponseEncryptionKey(
                    x = jwk.getString("x"),
                    y = jwk.getString("y"),
                    kid = jwk.optString("kid").ifEmpty { null },
                )
            }
            throw IllegalArgumentException(
                "client_metadata.jwks has no usable encryption key; this wallet " +
                    "implements ECDH-ES on P-256"
            )
        }

        /**
         * Which content encryption to use.
         *
         * OpenID4VP 1.0 §8.3 has the verifier list what it accepts, and
         * requires both GCM sizes, so the absent case is a verifier bug
         * rather than a choice — default to A128GCM and let it fail loudly
         * at the verifier if that was wrong.
         */
        private fun responseEncOf(clientMetadata: JSONObject): String {
            val supported = clientMetadata.optJSONArray("encrypted_response_enc_values_supported")
                ?: return SUPPORTED_ENC.first()
            val offered = (0 until supported.length()).map { supported.getString(it) }
            return SUPPORTED_ENC.firstOrNull { it in offered }
                ?: throw IllegalArgumentException(
                    "verifier accepts $offered for response encryption; this wallet " +
                        "implements $SUPPORTED_ENC"
                )
        }
    }
}

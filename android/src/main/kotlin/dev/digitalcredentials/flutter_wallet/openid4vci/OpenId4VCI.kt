package dev.digitalcredentials.flutter_wallet.openid4vci

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.contentType
import io.ktor.http.parameters
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.json.Json
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec
import kotlin.io.encoding.Base64 as KotlinBase64
import kotlin.io.encoding.ExperimentalEncodingApi

private const val TAG = "FlutterWallet"

/**
 * The wallet's side of an OpenID4VCI 1.0 pre-authorized-code issuance.
 *
 * Four calls: token, nonce, then a key proof, then the credential. The key is
 * generated in the Android KeyStore with the issuer's nonce as the attestation
 * challenge, and the resulting certificate chain *is* the proof — so the
 * private key never exists outside hardware, and the issuer can tell.
 *
 * What CMWallet does here and this does not: PAR, the authorization-code
 * grant, client attestation, DPoP (the issuer accepts plain Bearer), request
 * and response encryption, batch issuance, and the software-key proof
 * fallback. Hardware keys were the point.
 */
class OpenId4VCI(offerJson: String) {

    private val json = Json {
        explicitNulls = false
        ignoreUnknownKeys = true
        isLenient = true
    }

    val offer: CredentialOffer = json.decodeFromString(offerJson)

    private val httpClient = HttpClient(CIO) {
        install(ContentNegotiation) { json(json) }
    }

    /** The configuration being issued; the offer may name several, we take the first. */
    val configurationId: String = offer.credentialConfigurationIds.first()

    suspend fun requestToken(): TokenResponse {
        val grant = offer.grants?.preAuthorizedCode
            ?: throw UnsupportedOperationException(
                "this wallet only implements the pre-authorized code grant"
            )
        val endpoint = offer.authorizationServerMetadata?.tokenEndpoint
            ?: throw IllegalStateException(
                "the offer carries no token endpoint; fetching .well-known is not implemented"
            )

        val response = httpClient.submitForm(
            url = endpoint,
            formParameters = parameters {
                append("grant_type", GRANT_PRE_AUTHORIZED_CODE)
                append("pre-authorized_code", grant.preAuthorizedCode)
                append("tx_code", TX_CODE)
                append("client_id", WALLET_CLIENT_ID)
                append("scope", configurationId)
            },
        )
        val body = response.bodyAsText()
        Log.d(TAG, "token response: $body")
        if (!response.status.isSuccessOrRedirect()) {
            throw IllegalStateException("token endpoint returned ${response.status}: $body")
        }
        return json.decodeFromString(body)
    }

    suspend fun requestNonce(): String {
        val endpoint = offer.issuerMetadata.nonceEndpoint
            ?: throw IllegalStateException("the issuer advertises no nonce endpoint")
        val response: NonceResponse = httpClient.post(endpoint).body()
        return response.cNonce
    }

    /**
     * A hardware-backed key whose attestation chain proves possession.
     *
     * The issuer's nonce goes in as the attestation challenge, which is what
     * makes the chain a proof of this transaction rather than a replayable
     * artefact. Returns the alias, the public key, and the chain to send.
     */
    @OptIn(ExperimentalEncodingApi::class)
    fun createAttestationProof(nonce: String): KeyProof {
        val alias = "wallet-" + java.util.UUID.randomUUID().toString().replace("-", "")
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
        )
        generator.initialize(
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(nonce.toByteArray(Charsets.UTF_8))
                .build()
        )
        val keyPair = generator.generateKeyPair()

        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val chain = keyStore.getCertificateChain(alias)
            ?: throw IllegalStateException("no attestation chain for $alias")

        return KeyProof(
            keyAlias = alias,
            publicKey = keyPair.public,
            chain = chain.map { KotlinBase64.encode(it.encoded) },
        )
    }

    suspend fun requestCredential(accessToken: String, proof: KeyProof): CredentialResponse {
        val request = CredentialRequest(
            credentialConfigurationId = configurationId,
            proofs = Proofs(androidKeystoreAttestation = listOf(proof.chain)),
        )
        val response = httpClient.post(offer.issuerMetadata.credentialEndpoint) {
            // Bearer, not DPoP: the DPoP machinery was cut, and issuers that
            // advertise "token_type": "DPoP" still accept a plain bearer token.
            header(HttpHeaders.Authorization, "Bearer $accessToken")
            contentType(ContentType.Application.Json)
            setBody(request)
        }
        val body = response.bodyAsText()
        Log.d(TAG, "credential response: ${body.take(200)}")
        if (!response.status.isSuccessOrRedirect()) {
            throw IllegalStateException("credential endpoint returned ${response.status}: $body")
        }
        return json.decodeFromString(body)
    }

    private fun io.ktor.http.HttpStatusCode.isSuccessOrRedirect() = value in 200..399

    data class KeyProof(
        val keyAlias: String,
        val publicKey: PublicKey,
        val chain: List<String>,
    )

    companion object {
        const val WALLET_CLIENT_ID = "https://flutter-wallet.example.org"

        /**
         * Issuers in this ecosystem expect a tx_code on the pre-authorized
         * grant whether or not the offer asked for one; CMWallet hardcodes the
         * same value.
         */
        const val TX_CODE = "123456"
        const val GRANT_PRE_AUTHORIZED_CODE =
            "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    }
}

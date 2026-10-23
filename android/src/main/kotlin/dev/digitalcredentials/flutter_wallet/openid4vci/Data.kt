package dev.digitalcredentials.flutter_wallet.openid4vci

import dev.digitalcredentials.flutter_wallet.data.CredentialConfiguration
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * The OpenID4VCI 1.0 messages this wallet exchanges, and no more.
 *
 * Trimmed hard against what an issuer actually needs for the pre-authorized
 * code flow. Dropped from CMWallet's version: the authorization-code grant,
 * PAR, client attestation, DPoP, request/response encryption and batch
 * issuance. Each was dead weight for this flow, and several carried their own
 * retry paths.
 */

@Serializable
data class CredentialOffer(
    @SerialName("credential_issuer") val credentialIssuer: String,
    @SerialName("credential_configuration_ids") val credentialConfigurationIds: List<String>,
    @SerialName("credential_issuer_metadata") val issuerMetadata: IssuerMetadata,
    @SerialName("authorization_server_metadata") val authorizationServerMetadata: AuthorizationServerMetadata? = null,
    @SerialName("grants") val grants: Grants? = null,
)

@Serializable
data class IssuerMetadata(
    @SerialName("credential_issuer") val credentialIssuer: String,
    @SerialName("credential_endpoint") val credentialEndpoint: String,
    @SerialName("nonce_endpoint") val nonceEndpoint: String? = null,
    @SerialName("credential_configurations_supported")
    val credentialConfigurationsSupported: Map<String, CredentialConfiguration>,
)

@Serializable
data class AuthorizationServerMetadata(
    @SerialName("issuer") val issuer: String? = null,
    @SerialName("token_endpoint") val tokenEndpoint: String? = null,
)

@Serializable
data class Grants(
    @SerialName("urn:ietf:params:oauth:grant-type:pre-authorized_code")
    val preAuthorizedCode: GrantPreAuthorizedCode? = null,
)

@Serializable
data class GrantPreAuthorizedCode(
    @SerialName("pre-authorized_code") val preAuthorizedCode: String,
)

@Serializable
data class TokenResponse(
    @SerialName("access_token") val accessToken: String,
    @SerialName("token_type") val tokenType: String? = null,
    @SerialName("expires_in") val expiresInSeconds: Long? = null,
    @SerialName("scope") val scope: String? = null,
)

@Serializable
data class NonceResponse(
    @SerialName("c_nonce") val cNonce: String,
)

@Serializable
data class Proofs(
    @SerialName("jwt") val jwt: List<String>? = null,
    @SerialName("android_keystore_attestation")
    val androidKeystoreAttestation: List<List<String>>? = null,
)

@Serializable
data class CredentialRequest(
    @SerialName("credential_configuration_id") val credentialConfigurationId: String,
    @SerialName("proofs") val proofs: Proofs,
)

@Serializable
data class IssuedCredential(
    @SerialName("credential") val credential: String,
)

@Serializable
data class CredentialResponse(
    @SerialName("credentials") val credentials: List<IssuedCredential>? = null,
    @SerialName("display") val display: List<IssuedDisplay>? = null,
)

@Serializable
data class IssuedDisplay(
    @SerialName("name") val name: String? = null,
    @SerialName("description") val description: String? = null,
    @SerialName("locale") val locale: String? = null,
)

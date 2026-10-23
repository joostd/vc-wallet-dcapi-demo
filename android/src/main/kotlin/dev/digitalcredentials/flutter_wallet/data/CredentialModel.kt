package dev.digitalcredentials.flutter_wallet.data

import dev.digitalcredentials.flutter_wallet.decodeBase64UrlNoPadding
import dev.digitalcredentials.flutter_wallet.loadECPrivateKey
import dev.digitalcredentials.flutter_wallet.mdoc.MDoc
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.security.KeyStore
import java.security.PrivateKey

/**
 * The stored shape of a credential, kept wire-compatible with CMWallet's
 * databasenew.json so its test credentials can be used unchanged.
 *
 * Trimmed to mdoc: the sd-jwt configuration variant is gone, because without
 * a matching registry branch it would only fail later and less clearly.
 */
@Serializable
data class CredentialItem(
    val id: String,
    val config: CredentialConfiguration,
    val displayData: CredentialDisplayData,
    val credentials: List<Credential>,
)

@Serializable
data class Credential(
    val key: CredentialKey,
    val credential: String,
) {
    val mdoc: MDoc by lazy { MDoc(credential.decodeBase64UrlNoPadding()) }
}

@Serializable
sealed class CredentialKey

@Serializable
@SerialName("SOFTWARE")
data class CredentialKeySoftware(
    val publicKey: String,
    val privateKey: String,
) : CredentialKey()

@Serializable
@SerialName("HARDWARE")
data class CredentialKeyHardware(
    val publicKey: String,
    val keyAlias: String,
) : CredentialKey()

@Serializable
data class CredentialDisplayData(
    val title: String,
    val subtitle: String? = null,
    val icon: String? = null,
    val explainer: String? = null,
    val metadataDisplayText: String? = null,
)

/** Resolves to a usable signing key: in-process for software, KeyStore for hardware. */
fun CredentialKey.toPrivateKey(): PrivateKey = when (this) {
    is CredentialKeySoftware -> loadECPrivateKey(privateKey.decodeBase64UrlNoPadding())
    is CredentialKeyHardware -> {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        keyStore.getKey(keyAlias, null) as? PrivateKey
            ?: throw IllegalArgumentException("no private key for alias $keyAlias")
    }
}

// -- credential configuration ---------------------------------------------

@Serializable
data class ClaimDisplay(
    @SerialName("name") val name: String? = null,
    @SerialName("locale") val locale: String? = null,
)

@Serializable
data class Claim(
    @SerialName("path") val path: List<String>,
    @SerialName("display") val display: List<ClaimDisplay>? = null,
    @SerialName("mandatory") val mandatory: Boolean? = null,
)

@Serializable
data class ConfigurationDisplay(
    @SerialName("name") val name: String,
    @SerialName("locale") val locale: String? = null,
    @SerialName("description") val description: String? = null,
)

@Serializable
data class CredentialMetadata(
    @SerialName("display") val display: List<ConfigurationDisplay>? = null,
    @SerialName("claims") val claims: List<Claim>? = null,
)

@Serializable(with = CredentialConfigurationSerializer::class)
sealed class CredentialConfiguration {
    abstract val format: String
    abstract val credentialMetadata: CredentialMetadata?
}

@Serializable
data class CredentialConfigurationMDoc(
    @SerialName("format") override val format: String,
    @SerialName("credential_metadata") override val credentialMetadata: CredentialMetadata? = null,
    @SerialName("doctype") val doctype: String,
    @SerialName("scope") val scope: String? = null,
) : CredentialConfiguration()

/**
 * Kept as the serializer's fallback so an unexpected `format` surfaces as a
 * clear failure at registration rather than an exception inside kotlinx.
 */
@Serializable
data class CredentialConfigurationUnknownFormat(
    @SerialName("format") override val format: String,
    @SerialName("credential_metadata") override val credentialMetadata: CredentialMetadata? = null,
) : CredentialConfiguration()

/**
 * The issuer's label for a claim, falling back to the element identifier.
 *
 * Shared deliberately: the registry entry, the host-facing projection and
 * the issuance preview must all agree, or the same claim is named three
 * different ways in three different screens.
 */
fun CredentialConfigurationMDoc.displayNameFor(namespace: String, element: String): String =
    credentialMetadata?.claims
        ?.firstOrNull { it.path.size >= 2 && it.path[0] == namespace && it.path[1] == element }
        ?.display?.firstOrNull()?.name
        ?: element

object CredentialConfigurationSerializer :
    JsonContentPolymorphicSerializer<CredentialConfiguration>(CredentialConfiguration::class) {
    override fun selectDeserializer(element: JsonElement) =
        when (element.jsonObject["format"]?.jsonPrimitive?.content) {
            "mso_mdoc" -> CredentialConfigurationMDoc.serializer()
            else -> CredentialConfigurationUnknownFormat.serializer()
        }
}

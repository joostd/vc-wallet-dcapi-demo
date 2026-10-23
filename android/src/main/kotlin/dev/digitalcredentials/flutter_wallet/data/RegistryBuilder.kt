package dev.digitalcredentials.flutter_wallet.data

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.util.Log
import androidx.credentials.registry.digitalcredentials.mdoc.MdocEntry
import androidx.credentials.registry.digitalcredentials.mdoc.MdocField
import androidx.credentials.registry.digitalcredentials.openid4vp.OpenId4VpRegistry
import androidx.credentials.registry.provider.RegistryManager
import androidx.credentials.registry.provider.digitalcredentials.DigitalCredentialEntry
import androidx.credentials.registry.provider.digitalcredentials.VerificationEntryDisplayProperties
import androidx.credentials.registry.provider.digitalcredentials.VerificationFieldDisplayProperties
import dev.digitalcredentials.flutter_wallet.decodeBase64
import dev.digitalcredentials.flutter_wallet.decodeBase64UrlNoPadding
import dev.digitalcredentials.flutter_wallet.mdoc.MDoc

private const val TAG = "FlutterWallet"
const val REGISTRY_ID = "openid4vp1.0"

/**
 * Turns stored credentials into the registry Credential Manager matches
 * against, and registers it.
 *
 * Ported from CMWallet's CredentialRepository.createRegistry(), minus the
 * sd-jwt branch. One deliberate difference: this builds the registry through
 * the library's typed API, which supplies its own matcher, so no presentation
 * wasm is shipped. Only issuance needs a matcher blob.
 */
object RegistryBuilder {

    /** Registers every credential in the store. Suspends; call from a coroutine. */
    suspend fun register(context: Context, items: List<CredentialItem>) {
        val entries = items.mapNotNull { entryFor(context, it) }
        if (entries.isEmpty()) {
            Log.w(TAG, "no mdoc credentials to register")
        }
        // The alpha05 API is a constructor taking (entries, id); CMWallet's
        // snapshot had a create(context, entries, inlineIssuance) factory.
        val registry = OpenId4VpRegistry(entries, REGISTRY_ID)
        RegistryManager.create(context).registerCredentials(registry)
        Log.i(TAG, "registered ${entries.size} credential(s) under $REGISTRY_ID")
    }

    private fun entryFor(context: Context, item: CredentialItem): DigitalCredentialEntry? {
        val config = item.config as? CredentialConfigurationMDoc ?: run {
            Log.w(TAG, "skipping ${item.id}: unsupported format ${item.config.format}")
            return null
        }
        val mdoc = MDoc(item.credentials.first().credential.decodeBase64UrlNoPadding())

        val fields = mdoc.issuerSignedNamespaces.flatMap { (namespace, elements) ->
            elements.map { (element, value) ->
                val displayName = config.displayNameFor(namespace, element)
                MdocField(
                    namespace = namespace,
                    identifier = element,
                    fieldValue = value,
                    fieldDisplayPropertySet = setOf(
                        VerificationFieldDisplayProperties(
                            displayName = displayName,
                            displayValue = value as? String,
                        )
                    ),
                )
            }
        }

        return MdocEntry(
            docType = config.doctype,
            fields = fields,
            entryDisplayPropertySet = setOf(
                VerificationEntryDisplayProperties(
                    title = item.displayData.title,
                    subtitle = item.displayData.subtitle,
                    icon = item.displayData.icon?.decodeBase64()?.let {
                        BitmapFactory.decodeByteArray(it, 0, it.size)
                    } ?: fallbackIcon(context),
                    explainer = item.displayData.explainer,
                )
            ),
            id = item.id,
        )
    }

    /**
     * The entry display requires an icon. CMWallet uses the wallet's launcher
     * icon; a plugin has no icon of its own, so fall back to the host app's,
     * and to a blank bitmap if even that cannot be rasterised.
     */
    private fun fallbackIcon(context: Context): Bitmap {
        return try {
            val drawable = context.packageManager.getApplicationIcon(context.packageName)
            val width = drawable.intrinsicWidth.takeIf { it > 0 } ?: 96
            val height = drawable.intrinsicHeight.takeIf { it > 0 } ?: 96
            Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888).also { bitmap ->
                val canvas = Canvas(bitmap)
                drawable.setBounds(0, 0, canvas.width, canvas.height)
                drawable.draw(canvas)
            }
        } catch (e: Exception) {
            Log.w(TAG, "could not rasterise the host app icon", e)
            Bitmap.createBitmap(96, 96, Bitmap.Config.ARGB_8888)
        }
    }
}

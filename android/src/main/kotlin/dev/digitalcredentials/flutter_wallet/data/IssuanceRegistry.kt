package dev.digitalcredentials.flutter_wallet.data

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.util.Log
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.registry.provider.RegisterCreationOptionsRequest
import androidx.credentials.registry.provider.RegistryManager
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

private const val TAG = "FlutterWallet"

/**
 * Tells Credential Manager this app can *receive* credentials.
 *
 * Unlike presentation, there is no typed API for this yet: the creation
 * options are a hand-rolled binary blob and the matcher is a wasm module we
 * ship. Both are ported from CMWallet, which is the only documentation of
 * the format that exists.
 */
object IssuanceRegistry {

    private const val REGISTRY_ID = "openid4vci"
    private const val MATCHER_ASSET = "provision_hardcoded.wasm"

    @OptIn(ExperimentalDigitalCredentialApi::class)
    suspend fun register(context: Context, title: String, subtitle: String) {
        val matcher = context.assets.open(MATCHER_ASSET).use { it.readBytes() }
        val options = creationOptions(context, title, subtitle)

        RegistryManager.create(context).registerCreationOptions(
            object : RegisterCreationOptionsRequest(
                creationOptions = options,
                matcher = matcher,
                type = DigitalCredential.TYPE_DIGITAL_CREDENTIAL,
                id = REGISTRY_ID,
                intentAction = "",
            ) {}
        )
        Log.i(TAG, "registered issuance options under $REGISTRY_ID")
    }

    /**
     * The creation-options blob the matcher parses.
     *
     *   bytes 0..3    int32 little-endian: offset of the JSON
     *   bytes 4..N    icon bytes, concatenated
     *   bytes N..end  UTF-8 JSON
     *
     * `icon.start` is an absolute offset into the whole blob, which is why
     * the first icon sits at 4. The matcher parses the JSON with a
     * strlen-based reader, so it must be the last thing in the buffer.
     */
    private fun creationOptions(context: Context, title: String, subtitle: String): ByteArray {
        val icon = iconBytes(context)
        val out = ByteArrayOutputStream()

        out.write(
            ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(4 + icon.size).array()
        )
        out.write(icon)
        out.write(
            JSONObject().apply {
                put("display", JSONObject().apply {
                    put("title", title)
                    put("subtitle", subtitle)
                    put("icon", JSONObject().apply {
                        put("start", 4)
                        put("length", icon.size)
                    })
                })
            }.toString().toByteArray()
        )
        return out.toByteArray()
    }

    private fun iconBytes(context: Context): ByteArray {
        val bitmap = try {
            val drawable = context.packageManager.getApplicationIcon(context.packageName)
            Bitmap.createBitmap(
                drawable.intrinsicWidth.takeIf { it > 0 } ?: 96,
                drawable.intrinsicHeight.takeIf { it > 0 } ?: 96,
                Bitmap.Config.ARGB_8888,
            ).also {
                val canvas = Canvas(it)
                drawable.setBounds(0, 0, canvas.width, canvas.height)
                drawable.draw(canvas)
            }
        } catch (e: Exception) {
            Log.w(TAG, "could not rasterise the host app icon", e)
            Bitmap.createBitmap(96, 96, Bitmap.Config.ARGB_8888)
        }
        return ByteArrayOutputStream().also {
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, it)
        }.toByteArray()
    }
}

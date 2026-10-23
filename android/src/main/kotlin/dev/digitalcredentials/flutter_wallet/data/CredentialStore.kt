package dev.digitalcredentials.flutter_wallet.data

import android.content.Context
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import java.io.File

private val CREDENTIAL_LIST = ListSerializer(CredentialItem.serializer())

private const val TAG = "FlutterWallet"
private const val STORE_FILE = "wallet_credentials.json"

/**
 * Every credential the wallet holds, in one JSON file.
 *
 * CMWallet splits these across a Room database (issued) and an in-memory
 * source loaded from assets (bundled test data), which is why its UI shows
 * more credentials than its database contains. One list in one place is
 * easier to reason about, and at demo scale a file is enough — Room would
 * add an annotation processor for no benefit.
 */
class CredentialStore(private val context: Context) {

    private val json = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
        encodeDefaults = true
    }

    private val file: File get() = File(context.filesDir, STORE_FILE)

    private val _credentials = MutableStateFlow<List<CredentialItem>>(emptyList())
    val credentials: StateFlow<List<CredentialItem>> = _credentials

    init {
        _credentials.value = load()
    }

    private fun load(): List<CredentialItem> {
        if (!file.exists()) return emptyList()
        return try {
            json.decodeFromString(CREDENTIAL_LIST, file.readText())
        } catch (e: Exception) {
            // A store we cannot parse is worse than an empty one: it would make
            // every later failure look like a registration problem.
            Log.e(TAG, "credential store unreadable, starting empty", e)
            emptyList()
        }
    }

    private fun persist(items: List<CredentialItem>) {
        file.writeText(json.encodeToString(CREDENTIAL_LIST, items))
        _credentials.value = items
    }

    /** Add or replace by id. Returns the id. */
    fun put(item: CredentialItem): String {
        persist(_credentials.value.filterNot { it.id == item.id } + item)
        Log.i(TAG, "stored credential ${item.id} (${item.displayData.title})")
        return item.id
    }

    /** Add several at once, replacing by id; one write, one registration. */
    fun putAll(items: List<CredentialItem>) {
        val incoming = items.associateBy { it.id }
        persist(_credentials.value.filterNot { it.id in incoming } + items)
        Log.i(TAG, "stored ${items.size} credential(s)")
    }

    fun remove(id: String) {
        persist(_credentials.value.filterNot { it.id == id })
    }

    fun get(id: String): CredentialItem? = _credentials.value.firstOrNull { it.id == id }

    fun parse(jsonText: String): List<CredentialItem> =
        json.decodeFromString(CREDENTIAL_LIST, jsonText)
}

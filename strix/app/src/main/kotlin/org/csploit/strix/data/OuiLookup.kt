package org.csploit.strix.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.csploit.strix.core.Logger
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class OuiLookup @Inject constructor(
    private val toolManager: ToolManager,
) {
    private val loadMutex = Mutex()

    @Volatile
    private var cache: Map<String, String>? = null

    /**
     * Vendor for [mac], or null. Loads nmap-mac-prefixes once, off the main
     * thread. Longest-prefix match: MA-S (9 hex), MA-M (7 hex), MA-L/OUI (6 hex).
     */
    suspend fun identify(mac: String?): String? {
        val hex = normalizeMac(mac) ?: return null
        return lookup(getDatabase(), hex)
    }

    private suspend fun getDatabase(): Map<String, String> {
        cache?.let { return it }
        return loadMutex.withLock {
            cache ?: withContext(Dispatchers.IO) { load() }
        }
    }

    private fun load(): Map<String, String> {
        val file = File(toolManager.toolsPath, "share/nmap/nmap-mac-prefixes")
        if (!file.exists()) {
            // Not cached: tools may still be extracting; retry on next lookup.
            Logger.warning("OuiLookup: nmap-mac-prefixes not found")
            return emptyMap()
        }
        val db = HashMap<String, String>(65536)
        try {
            file.bufferedReader().useLines { lines -> lines.forEach { parseLine(it, db) } }
            Logger.info("OuiLookup: loaded ${db.size} entries")
        } catch (e: Exception) {
            Logger.error("OuiLookup: load failed: ${e.message}")
        }
        cache = db
        return db
    }

    companion object {
        private val PREFIX_LENGTHS = listOf(9, 7, 6)
        private val HEX12 = Regex("[0-9A-F]{12}")

        /**
         * Normalizes "aa:bb:cc:dd:ee:ff", "AA-BB-...", "aabb.ccdd.eeff",
         * "a:b:c:d:e:f" (single-digit octets) or bare hex to 12 upper-case
         * hex digits. Returns null for anything else (e.g. "manual").
         */
        fun normalizeMac(mac: String?): String? {
            val parts = mac?.trim()?.uppercase()?.split(':', '-', '.') ?: return null
            val hex = if (parts.size == 6) {
                parts.joinToString("") { it.padStart(2, '0') }
            } else {
                parts.joinToString("")
            }
            return hex.takeIf { HEX12.matches(it) }
        }

        internal fun parseLine(line: String, into: MutableMap<String, String>) {
            if (line.isEmpty() || line.startsWith("#")) return
            val parts = line.split(" ", limit = 2)
            if (parts.size == 2) into[parts[0].uppercase()] = parts[1].trim()
        }

        internal fun lookup(db: Map<String, String>, hex: String): String? =
            PREFIX_LENGTHS.firstNotNullOfOrNull { db[hex.take(it)] }
    }
}

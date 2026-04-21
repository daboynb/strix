package org.csploit.strix.data

import org.csploit.strix.core.Logger
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class OuiLookup @Inject constructor(
    private val toolManager: ToolManager,
) {
    private var cache: Map<String, String>? = null

    fun identify(mac: String?): String? {
        if (mac == null) return null
        val oui = mac.uppercase().replace(":", "").take(6)
        return getDatabase()[oui]
    }

    private fun getDatabase(): Map<String, String> {
        cache?.let { return it }
        val db = mutableMapOf<String, String>()
        val file = File(toolManager.toolsPath, "share/nmap/nmap-mac-prefixes")
        if (!file.exists()) {
            Logger.warning("OuiLookup: nmap-mac-prefixes not found")
            return db
        }
        try {
            file.bufferedReader().useLines { lines ->
                lines.forEach { line ->
                    if (line.isNotEmpty() && !line.startsWith("#")) {
                        val parts = line.split(" ", limit = 2)
                        if (parts.size == 2) {
                            db[parts[0].uppercase()] = parts[1]
                        }
                    }
                }
            }
            Logger.info("OuiLookup: loaded ${db.size} entries")
        } catch (e: Exception) {
            Logger.error("OuiLookup: load failed: ${e.message}")
        }
        cache = db
        return db
    }
}

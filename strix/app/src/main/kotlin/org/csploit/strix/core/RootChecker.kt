package org.csploit.strix.core

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class RootChecker @Inject constructor() {

    suspend fun isRootAvailable(): Boolean = withContext(Dispatchers.IO) {
        try {
            val process = ProcessBuilder("su", "-c", "id").start()
            val output = BufferedReader(InputStreamReader(process.inputStream))
                .use { it.readLine() }
            val exitCode = process.waitFor()
            val hasRoot = exitCode == 0 && output != null && output.contains("uid=0")
            Logger.info("RootChecker: su -c id => exit=$exitCode output=$output hasRoot=$hasRoot")
            hasRoot
        } catch (e: Exception) {
            Logger.error("RootChecker: su not available: ${e.message}")
            false
        }
    }
}

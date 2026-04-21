package org.csploit.strix.data

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.csploit.strix.core.Logger
import org.csploit.strix.core.ProcessEvent
import org.csploit.strix.core.ProcessManager
import org.csploit.strix.domain.model.DefaultCreds
import java.io.File
import java.net.URL
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class CredentialTester @Inject constructor(
    @ApplicationContext private val context: Context,
    private val processManager: ProcessManager,
    private val toolManager: ToolManager,
) {
    suspend fun test(
        ip: String,
        adminUrl: String,
        wwwAuthenticate: String?,
        onStatus: (String) -> Unit = {},
    ): DefaultCreds? = withContext(Dispatchers.IO) {
        val (usersFile, passwordsFile) = ensureRouterWordlists()

        val url = try { URL(adminUrl) } catch (_: Exception) { null }
        val port = url?.port?.let {
            if (it == -1) (if (url.protocol == "https") 443 else 80) else it
        } ?: 80
        val useSsl = url?.protocol == "https" || port == 443 || port == 8443
        val module = if (useSsl) "https-get" else "http-get"

        onStatus("Starting hydra $module on $ip:$port")
        Logger.info("CredentialTester: hydra $module on $ip:$port")

        var found: DefaultCreds? = null
        val credRegex = Regex("""\[\d+]\[\S+]\s+host:\s+\S+\s+login:\s+(\S+)\s+password:\s*(.*)""")
        val statusRegex = Regex("""\[STATUS]\s*(.+)""")

        processManager.execute(
            command = "hydra -L '${usersFile.absolutePath}' -P '${passwordsFile.absolutePath}' -f -t 4 -s $port $ip $module /",
            toolsDir = toolManager.toolsPath,
            workDir = toolManager.corePath,
        ).collect { event ->
            when (event) {
                is ProcessEvent.StdoutLine -> {
                    credRegex.find(event.line)?.let { match ->
                        found = DefaultCreds(
                            match.groupValues[1],
                            match.groupValues[2].trim(),
                            "$module :$port",
                        )
                        onStatus("Found: ${match.groupValues[1]}:${match.groupValues[2].trim()}")
                    }
                    statusRegex.find(event.line)?.let {
                        onStatus(it.groupValues[1].trim())
                    }
                    if (event.line.contains("attacking")) {
                        onStatus(event.line.trim())
                    }
                }
                is ProcessEvent.StderrLine -> {
                    Logger.debug("hydra stderr: ${event.line}")
                }
                is ProcessEvent.Exited -> {
                    onStatus(if (found != null) "Credentials found!" else "Finished - no credentials found")
                }
                is ProcessEvent.Killed -> {
                    onStatus("Stopped")
                }
            }
        }
        found
    }

    fun getWordlistPaths(): Pair<String, String> {
        val (u, p) = ensureGeneralWordlists()
        return u.absolutePath to p.absolutePath
    }

    private fun ensureRouterWordlists(): Pair<File, File> {
        val usersFile = File(toolManager.corePath, "router-users.txt")
        val passwordsFile = File(toolManager.corePath, "router-passwords.txt")
        extractAssetIfMissing("router-users.txt", usersFile)
        extractAssetIfMissing("router-passwords.txt", passwordsFile)
        return usersFile to passwordsFile
    }

    private fun ensureGeneralWordlists(): Pair<File, File> {
        val usersFile = File(toolManager.corePath, "users.txt")
        val passwordsFile = File(toolManager.corePath, "passwords.txt")
        extractAssetIfMissing("users.txt", usersFile)
        extractAssetIfMissing("passwords.txt", passwordsFile)
        return usersFile to passwordsFile
    }

    private fun extractAssetIfMissing(assetName: String, target: File) {
        if (target.exists()) return
        context.assets.open(assetName).use { input ->
            target.outputStream().use { output -> input.copyTo(output) }
        }
        target.setReadable(true, false)
    }
}

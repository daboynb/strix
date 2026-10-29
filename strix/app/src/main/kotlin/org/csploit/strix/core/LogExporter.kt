package org.csploit.strix.core

import android.content.Context
import android.net.Uri
import android.os.Build
import androidx.core.content.FileProvider
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.csploit.strix.data.ToolManager
import java.io.File
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import javax.inject.Inject
import javax.inject.Singleton

/** Builds cacheDir/exports/strix-log-<timestamp>.txt (device header + redacted log) for sharing. */
@Singleton
class LogExporter @Inject constructor(
    @ApplicationContext private val context: Context,
    private val toolManager: ToolManager,
    private val rootChecker: RootChecker,
) {
    suspend fun export(): Uri = withContext(Dispatchers.IO) {
        val dir = File(context.cacheDir, EXPORT_DIR).apply { mkdirs() }
        // Only the newest export is kept; share targets read it right away.
        dir.listFiles()?.forEach { it.delete() }
        val stamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"))
        val file = File(dir, "strix-log-$stamp.txt")
        file.writeText(LogFormat.redact(header() + "\n" + Logger.readLog()))
        FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
    }

    private fun header(): String {
        val pkg = runCatching { context.packageManager.getPackageInfo(context.packageName, 0) }.getOrNull()
        val root = when (rootChecker.lastResult) {
            true -> "available"
            false -> "NOT available"
            null -> "not checked"
        }
        val tools = runCatching {
            toolManager.installedToolsVersion()?.let { "$it (${toolManager.toolsSource()})" }
        }.getOrNull() ?: "not installed"
        val msf = runCatching { toolManager.installedMsfVersion() }.getOrNull() ?: "not installed"
        return buildString {
            appendLine("=== Strix log export ${LocalDateTime.now()} ===")
            appendLine("App: ${pkg?.versionName} (${pkg?.longVersionCode})")
            appendLine("Android: ${Build.VERSION.RELEASE} (SDK ${Build.VERSION.SDK_INT}), build ${Build.DISPLAY}")
            appendLine("Device: ${Build.MANUFACTURER} ${Build.MODEL}")
            appendLine("ABI: ${Build.SUPPORTED_ABIS.joinToString()}")
            appendLine("Root: $root")
            appendLine("Tools bundle: $tools")
            appendLine("MSF bundle: $msf")
            appendLine("SSID/BSSID values are redacted.")
            appendLine("===")
        }
    }

    companion object {
        const val EXPORT_DIR = "exports"
    }
}

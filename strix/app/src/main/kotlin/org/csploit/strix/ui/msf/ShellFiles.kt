package org.csploit.strix.ui.msf

import android.content.Context
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.csploit.strix.core.Logger
import java.io.File

/** Local dir where meterpreter downloads/screenshots land; created on demand. */
internal fun msfDownloadsDir(corePath: String): File {
    val dir = File(corePath, "msf_downloads")
    if (!dir.exists()) dir.mkdirs()
    return dir
}

/** Copy a picked file into files dir so the absolute path is stable (meterpreter's upload needs a fs path). */
internal suspend fun copyUriToMsfUploads(context: Context, corePath: String, uri: Uri): String? = withContext(Dispatchers.IO) {
    try {
        val name = queryDisplayName(context, uri) ?: "upload_${System.currentTimeMillis()}"
        val dir = File(corePath, "msf_uploads")
        if (!dir.exists()) dir.mkdirs()
        val out = File(dir, name)
        context.contentResolver.openInputStream(uri)?.use { input ->
            out.outputStream().use { input.copyTo(it) }
        }
        out.setReadable(true, false)
        out.absolutePath
    } catch (e: Exception) {
        Logger.warning("ShellVM: copyUriToFiles failed: ${e.message}")
        null
    }
}

private fun queryDisplayName(context: Context, uri: Uri): String? {
    return runCatching {
        context.contentResolver.query(uri, null, null, null, null)?.use { c ->
            val idx = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            if (idx >= 0 && c.moveToFirst()) c.getString(idx) else null
        }
    }.getOrNull()
}

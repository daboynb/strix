package org.csploit.strix.ui.bruteforce

import android.content.Context
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.csploit.strix.core.Logger
import org.csploit.strix.data.ToolManager
import java.io.File

/** Copy a picked wordlist into the core dir (world-readable for hydra); null on failure. */
internal suspend fun copyUriToInternal(
    context: Context,
    toolManager: ToolManager,
    uri: Uri,
    name: String,
): String? =
    withContext(Dispatchers.IO) {
        try {
            val outFile = File(toolManager.corePath, name)
            context.contentResolver.openInputStream(uri)?.use { input ->
                outFile.outputStream().use { input.copyTo(it) }
            }
            outFile.setReadable(true, false)
            outFile.absolutePath
        } catch (e: Exception) {
            Logger.warning("copyUriToInternal failed: ${e.message}")
            null
        }
    }

package org.csploit.strix.ui.msf

import android.content.Context
import android.net.Uri
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.csploit.strix.core.Logger
import org.csploit.strix.data.MsfRpcClient
import org.csploit.strix.data.ToolManager
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.inject.Inject

enum class SessionKind { SHELL, METERPRETER, UNKNOWN }

sealed interface ShellDialog {
    data class Upload(val pickedUri: Uri? = null, val sourcePath: String? = null) : ShellDialog
    data object Download : ShellDialog
    data class ScreenshotPreview(val path: String) : ShellDialog
}

data class ShellUiState(
    val sessionId: Int = 0,
    val kind: SessionKind = SessionKind.UNKNOWN,
    val output: List<String> = emptyList(),
    val input: String = "",
    val dialog: ShellDialog? = null,
    val pendingScreenshotPath: String? = null,
    val error: String? = null,
    /** Session no longer exists (or the daemon is unreachable): polling stopped, input disabled. */
    val sessionClosed: Boolean = false,
)

@HiltViewModel
class ShellViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
    savedStateHandle: SavedStateHandle,
    private val rpcClient: MsfRpcClient,
    private val toolManager: ToolManager,
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        ShellUiState(sessionId = savedStateHandle["sessionId"] ?: 0),
    )
    val uiState: StateFlow<ShellUiState> = _uiState.asStateFlow()

    private var pollJob: Job? = null

    init {
        detectKindThenStartPolling()
    }

    fun updateInput(input: String) {
        _uiState.value = _uiState.value.copy(input = input)
    }

    fun clearError() {
        _uiState.update { it.copy(error = null) }
    }

    fun sendCommand() {
        if (_uiState.value.sessionClosed) return
        val cmd = _uiState.value.input.trim()
        if (cmd.isEmpty()) return
        _uiState.value = _uiState.value.copy(input = "")
        send(cmd)
    }

    /** Write [cmd] on the session using the method appropriate for its kind. */
    fun send(cmd: String) {
        if (_uiState.value.sessionClosed) return
        val sid = _uiState.value.sessionId
        val kind = _uiState.value.kind
        viewModelScope.launch {
            try {
                appendOutput("$ $cmd")
                when (kind) {
                    SessionKind.METERPRETER -> rpcClient.meterpreterRunSingle(sid, cmd)
                    else -> rpcClient.shellWrite(sid, cmd + "\n")
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                _uiState.update { it.copy(error = "Send failed: ${e.message}") }
            }
        }
    }

    // --- Upload flow ---

    fun openUploadDialog() {
        _uiState.value = _uiState.value.copy(dialog = ShellDialog.Upload())
    }

    /** Called when the user picks a file; copies it into files dir so the
     *  absolute path is stable (meterpreter's upload needs a fs path). */
    fun setUploadSource(uri: Uri) {
        viewModelScope.launch(Dispatchers.IO) {
            val path = copyUriToFiles(uri)
            _uiState.value = _uiState.value.copy(
                dialog = ShellDialog.Upload(pickedUri = uri, sourcePath = path),
            )
        }
    }

    fun confirmUpload(remotePath: String) {
        val state = _uiState.value
        val dlg = state.dialog as? ShellDialog.Upload ?: return
        val src = dlg.sourcePath ?: return
        val dst = remotePath.trim().ifEmpty { "./" + File(src).name }
        _uiState.value = state.copy(dialog = null)
        send("upload \"$src\" \"$dst\"")
    }

    // --- Download flow ---

    fun openDownloadDialog() {
        _uiState.value = _uiState.value.copy(dialog = ShellDialog.Download)
    }

    fun confirmDownload(remotePath: String) {
        val remote = remotePath.trim()
        if (remote.isEmpty()) {
            _uiState.value = _uiState.value.copy(dialog = null)
            return
        }
        val local = File(downloadsDir(), File(remote).name).absolutePath
        _uiState.value = _uiState.value.copy(dialog = null)
        send("download \"$remote\" \"$local\"")
        appendOutput("[*] local destination: $local")
    }

    // --- Screenshot flow ---

    fun takeScreenshot() {
        val ts = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val path = File(downloadsDir(), "screenshot_$ts.jpeg").absolutePath
        _uiState.value = _uiState.value.copy(pendingScreenshotPath = path)
        send("screenshot -p \"$path\"")
        // Poll the file up to ~15s; meterpreter writes it synchronously but we give it room.
        viewModelScope.launch {
            val file = File(path)
            repeat(30) {
                delay(500)
                if (file.exists() && file.length() > 0) {
                    _uiState.value = _uiState.value.copy(
                        dialog = ShellDialog.ScreenshotPreview(path),
                        pendingScreenshotPath = null,
                    )
                    return@launch
                }
            }
            appendOutput("[!] screenshot timed out (file not found at $path)")
            _uiState.value = _uiState.value.copy(pendingScreenshotPath = null)
        }
    }

    fun dismissDialog() {
        _uiState.value = _uiState.value.copy(dialog = null)
    }

    // --- helpers ---

    private fun downloadsDir(): File {
        val dir = File(toolManager.corePath, "msf_downloads")
        if (!dir.exists()) dir.mkdirs()
        return dir
    }

    private suspend fun copyUriToFiles(uri: Uri): String? = withContext(Dispatchers.IO) {
        try {
            val name = queryDisplayName(uri) ?: "upload_${System.currentTimeMillis()}"
            val dir = File(toolManager.corePath, "msf_uploads")
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

    private fun queryDisplayName(uri: Uri): String? {
        return runCatching {
            context.contentResolver.query(uri, null, null, null, null)?.use { c ->
                val idx = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                if (idx >= 0 && c.moveToFirst()) c.getString(idx) else null
            }
        }.getOrNull()
    }

    private fun detectKindThenStartPolling() {
        viewModelScope.launch {
            val sid = _uiState.value.sessionId
            val (kind, rawType) = runCatching {
                val sessions = rpcClient.sessionList()
                val type = sessions.firstOrNull { it.id == sid }?.type ?: ""
                val k = when {
                    type.contains("meterpreter", ignoreCase = true) -> SessionKind.METERPRETER
                    type.contains("shell", ignoreCase = true) -> SessionKind.SHELL
                    else -> SessionKind.UNKNOWN
                }
                k to type
            }.getOrElse { SessionKind.UNKNOWN to "sessionList failed: ${it.message}" }
            Logger.info("ShellVM: session $sid kind=$kind rawType='$rawType'")
            _uiState.value = _uiState.value.copy(kind = kind)
            startPolling()
        }
    }

    private fun startPolling() {
        pollJob?.cancel()
        pollJob = viewModelScope.launch {
            delay(500)
            var failures = 0
            while (isActive) {
                val sid = _uiState.value.sessionId
                try {
                    val data = when (_uiState.value.kind) {
                        SessionKind.METERPRETER -> rpcClient.meterpreterRead(sid)
                        else -> rpcClient.shellRead(sid)
                    }
                    if (failures > 0) {
                        failures = 0
                        _uiState.update { it.copy(error = null) }
                    }
                    if (data.isNotEmpty()) {
                        data.lines().filter { it.isNotEmpty() }.forEach { appendOutput(it) }
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    failures++
                    // A dead session fails every read: confirm against
                    // session.list and stop instead of flooding the console.
                    val stillOpen = runCatching { rpcClient.sessionList().any { it.id == sid } }
                        .getOrNull()
                    if (stillOpen == false || failures >= MAX_READ_FAILURES) {
                        val reason = if (stillOpen == false) "session closed" else "connection lost: ${e.message}"
                        appendOutput("[session $sid $reason]")
                        _uiState.update { it.copy(sessionClosed = true, error = "Session $sid $reason") }
                        Logger.info("ShellVM: stop polling session $sid ($reason)")
                        return@launch
                    }
                    if (failures == 1) appendOutput("[read error: ${e.message}]")
                    _uiState.update { it.copy(error = "Read failed: ${e.message} (retrying)") }
                }
                // Back off while reads fail: 300ms, 600ms, 1.2s, ... capped.
                val backoff = if (failures == 0) POLL_INTERVAL_MS else
                    (POLL_INTERVAL_MS shl failures.coerceAtMost(4)).coerceAtMost(MAX_BACKOFF_MS)
                delay(backoff)
            }
        }
    }

    private fun appendOutput(line: String) {
        _uiState.update { state ->
            val next = state.output + line
            state.copy(output = if (next.size > 1000) next.takeLast(1000) else next)
        }
    }

    override fun onCleared() {
        pollJob?.cancel()
        super.onCleared()
    }

    private companion object {
        const val POLL_INTERVAL_MS = 300L
        const val MAX_BACKOFF_MS = 5_000L
        const val MAX_READ_FAILURES = 6
    }
}

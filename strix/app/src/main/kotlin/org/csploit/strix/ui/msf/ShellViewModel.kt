package org.csploit.strix.ui.msf

import android.content.Context
import android.net.Uri
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
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

    fun sendCommand() {
        val cmd = _uiState.value.input.trim()
        if (cmd.isEmpty()) return
        _uiState.value = _uiState.value.copy(input = "")
        send(cmd)
    }

    /** Write [cmd] on the session using the method appropriate for its kind. */
    fun send(cmd: String) {
        val sid = _uiState.value.sessionId
        val kind = _uiState.value.kind
        viewModelScope.launch {
            try {
                appendOutput("$ $cmd")
                when (kind) {
                    SessionKind.METERPRETER -> rpcClient.meterpreterRunSingle(sid, cmd)
                    else -> rpcClient.shellWrite(sid, cmd + "\n")
                }
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = "Send failed: ${e.message}")
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
            while (isActive) {
                try {
                    val data = when (_uiState.value.kind) {
                        SessionKind.METERPRETER -> rpcClient.meterpreterRead(_uiState.value.sessionId)
                        else -> rpcClient.shellRead(_uiState.value.sessionId)
                    }
                    if (data.isNotEmpty()) {
                        data.lines().filter { it.isNotEmpty() }.forEach { appendOutput(it) }
                    }
                } catch (e: Exception) {
                    appendOutput("[read error: ${e.message}]")
                }
                delay(300)
            }
        }
    }

    private fun appendOutput(line: String) {
        val current = _uiState.value.output.toMutableList()
        current.add(line)
        if (current.size > 1000) {
            _uiState.value = _uiState.value.copy(output = current.takeLast(1000))
        } else {
            _uiState.value = _uiState.value.copy(output = current)
        }
    }

    override fun onCleared() {
        pollJob?.cancel()
        super.onCleared()
    }
}

package org.csploit.strix.ui.msf

import android.net.Uri

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

/** Map a session.list `type` to how the shell reads/writes it. */
internal fun sessionKindOf(type: String): SessionKind = when {
    type.contains("meterpreter", ignoreCase = true) -> SessionKind.METERPRETER
    type.contains("shell", ignoreCase = true) -> SessionKind.SHELL
    else -> SessionKind.UNKNOWN
}

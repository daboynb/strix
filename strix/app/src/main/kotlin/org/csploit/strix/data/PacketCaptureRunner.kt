package org.csploit.strix.data

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.csploit.strix.core.Logger
import org.csploit.strix.core.ProcessEvent
import org.csploit.strix.core.ProcessManager
import javax.inject.Inject
import javax.inject.Singleton

data class PacketCaptureSession(
    val key: String,
    val filter: String,
    val verbose: Boolean,
    val iface: String,
    val isRunning: Boolean = false,
    val packetCount: Int = 0,
    val logLines: List<String> = emptyList(),
)

@Singleton
class PacketCaptureRunner @Inject constructor(
    private val processManager: ProcessManager,
    private val toolManager: ToolManager,
    private val networkManager: NetworkManager,
) {
    companion object {
        private const val LOG_LIMIT = 500
    }

    private val _sessions = MutableStateFlow<Map<String, PacketCaptureSession>>(emptyMap())
    val sessions: StateFlow<Map<String, PacketCaptureSession>> = _sessions.asStateFlow()

    fun sessionOf(key: String): PacketCaptureSession? = _sessions.value[key]

    fun clear(key: String) {
        _sessions.value = _sessions.value - key
    }

    /** Capture tcpdump output; publishes log lines and packet count into [sessions]. */
    suspend fun capture(key: String, filter: String = "", verbose: Boolean = false) {
        val net = networkManager.detectNetwork()
            ?: error("No WiFi network detected")

        val command = buildCommand(net.interfaceName, filter, verbose)
        Logger.info("PacketCaptureRunner: $command")

        updateSession(key) {
            PacketCaptureSession(
                key = key,
                filter = filter,
                verbose = verbose,
                iface = net.interfaceName,
                isRunning = true,
            )
        }
        try {
            processManager.execute(
                command = command,
                toolsDir = toolManager.toolsPath,
                workDir = toolManager.corePath,
            ).collect { event ->
                when (event) {
                    is ProcessEvent.StdoutLine -> {
                        appendLog(key, event.line)
                        if (event.line.isNotBlank() && !event.line.startsWith("tcpdump:")) {
                            updateSession(key) { it.copy(packetCount = it.packetCount + 1) }
                        }
                    }
                    is ProcessEvent.StderrLine -> appendLog(key, event.line)
                    is ProcessEvent.Exited -> appendLog(key, "[exited: ${event.code}]")
                    is ProcessEvent.Killed -> appendLog(key, "[killed: signal ${event.signal}]")
                }
            }
        } finally {
            updateSession(key) { it.copy(isRunning = false) }
        }
    }

    fun appendLog(key: String, line: String) {
        updateSession(key) {
            val next = it.logLines + line
            it.copy(logLines = if (next.size > LOG_LIMIT) next.takeLast(LOG_LIMIT) else next)
        }
    }

    private fun buildCommand(iface: String, filter: String, verbose: Boolean): String = buildString {
        append("tcpdump -i ").append(iface)
        append(" -n -l")
        if (verbose) append(" -v")
        if (filter.isNotBlank()) {
            append(" ").append(filter.trim())
        }
    }

    private inline fun updateSession(key: String, transform: (PacketCaptureSession) -> PacketCaptureSession) {
        val current = _sessions.value
        val existing = current[key] ?: PacketCaptureSession(
            key = key, filter = "", verbose = false, iface = "",
        )
        _sessions.value = current + (key to transform(existing))
    }
}

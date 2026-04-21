package org.csploit.strix.data

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.csploit.strix.core.Logger
import org.csploit.strix.core.ProcessEvent
import org.csploit.strix.core.ProcessManager
import org.csploit.strix.domain.model.PortInfo
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Per-target state of a port scan run. Lives in the [PortScanner] singleton so
 * it survives ViewModel destruction — when the user navigates away and returns,
 * the UI can rehydrate from here.
 */
data class PortScanSession(
    val ip: String,
    val isScanning: Boolean = false,
    val ports: List<PortInfo> = emptyList(),
    val os: String? = null,
    val progress: String? = null,
    val error: String? = null,
)

@Singleton
class PortScanner @Inject constructor(
    private val processManager: ProcessManager,
    private val toolManager: ToolManager,
    private val appSettings: AppSettings,
) {
    companion object {
        // Matches: 80/tcp  open  http    Apache httpd 2.4.41
        private val PORT_REGEX = Regex(
            """(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)\s*(.*)"""
        )
        private val OS_REGEX = Regex("""OS details:\s*(.+)""")
        private val PROGRESS_REGEX = Regex("""(\d+\.\d+)% done""")
    }

    private val _sessions = MutableStateFlow<Map<String, PortScanSession>>(emptyMap())
    val sessions: StateFlow<Map<String, PortScanSession>> = _sessions.asStateFlow()

    fun sessionOf(ip: String): PortScanSession? = _sessions.value[ip]

    /**
     * Run nmap service/version scan against [ip], publishing progress into
     * [sessions]. Suspends until nmap exits or the caller cancels.
     *
     * Cancellation kills the underlying process via ProcessManager's awaitClose.
     * Session is NOT removed on cancel — partial results stay visible.
     */
    suspend fun scan(ip: String, portRange: String? = null) {
        val range = portRange?.ifBlank { null } ?: appSettings.defaultPortRange.ifBlank { null }
        val portArg = if (range == null) "--top-ports 1000" else "-p $range"
        val timing = appSettings.nmapTiming
        val dnsArg = appSettings.dnsServer.ifBlank { null }?.let { "--dns-servers $it" } ?: ""
        val extraArgs = appSettings.customNmapArgs.trim()

        updateSession(ip) {
            PortScanSession(ip = ip, isScanning = true, ports = emptyList(), os = null, progress = null, error = null)
        }

        try {
            processManager.execute(
                command = "nmap -sS -sV -O $portArg -T$timing -Pn $dnsArg $extraArgs $ip",
                toolsDir = toolManager.toolsPath,
                workDir = toolManager.corePath,
            ).collect { event ->
                when (event) {
                    is ProcessEvent.StdoutLine -> {
                        val line = event.line

                        PORT_REGEX.find(line)?.let { match ->
                            val port = PortInfo(
                                number = match.groupValues[1].toInt(),
                                protocol = match.groupValues[2],
                                state = match.groupValues[3],
                                service = match.groupValues[4].ifBlank { null },
                                version = match.groupValues[5].trim().ifBlank { null },
                            )
                            updateSession(ip) { it.copy(ports = it.ports + port) }
                        }

                        OS_REGEX.find(line)?.let { match ->
                            updateSession(ip) { it.copy(os = match.groupValues[1].trim()) }
                        }

                        PROGRESS_REGEX.find(line)?.let { match ->
                            updateSession(ip) { it.copy(progress = "${match.groupValues[1]}%") }
                        }
                    }
                    is ProcessEvent.StderrLine -> Logger.debug("nmap stderr: ${event.line}")
                    is ProcessEvent.Exited -> {
                        if (event.code != 0) {
                            updateSession(ip) { it.copy(error = "nmap exited with code ${event.code}") }
                        }
                    }
                    is ProcessEvent.Killed -> {
                        updateSession(ip) { it.copy(error = "nmap killed by signal ${event.signal}") }
                    }
                }
            }
        } finally {
            updateSession(ip) { it.copy(isScanning = false, progress = null) }
        }
    }

    /** Wipe the stored session for [ip] (e.g. the user restarts the scan). */
    fun clear(ip: String) {
        _sessions.value = _sessions.value - ip
    }

    private inline fun updateSession(ip: String, transform: (PortScanSession) -> PortScanSession) {
        val current = _sessions.value
        val existing = current[ip] ?: PortScanSession(ip = ip)
        _sessions.value = current + (ip to transform(existing))
    }
}

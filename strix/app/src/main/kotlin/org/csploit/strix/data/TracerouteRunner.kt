package org.csploit.strix.data

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.csploit.strix.core.Logger
import org.csploit.strix.core.ProcessEvent
import org.csploit.strix.core.ProcessManager
import org.csploit.strix.domain.model.TracerouteHop
import javax.inject.Inject
import javax.inject.Singleton

data class TracerouteSession(
    val ip: String,
    val isTracing: Boolean = false,
    val hops: List<TracerouteHop> = emptyList(),
    val error: String? = null,
)

@Singleton
class TracerouteRunner @Inject constructor(
    private val processManager: ProcessManager,
    private val toolManager: ToolManager,
) {
    companion object {
        private val HOP_REGEX = Regex("""^\s*(\d+)\s+(.+)$""")
        private val RTT_ADDR_REGEX = Regex("""(\d+\.?\d*)\s+ms\s+(.+)""")
        private val HOST_IP_REGEX = Regex("""^(.+?)\s+\(([0-9.]+)\)$""")
    }

    private val _sessions = MutableStateFlow<Map<String, TracerouteSession>>(emptyMap())
    val sessions: StateFlow<Map<String, TracerouteSession>> = _sessions.asStateFlow()

    fun sessionOf(ip: String): TracerouteSession? = _sessions.value[ip]

    fun clear(ip: String) {
        _sessions.value = _sessions.value - ip
    }

    /** Run nmap --traceroute, publishing hops and end-state into [sessions]. */
    suspend fun trace(ip: String) {
        updateSession(ip) { TracerouteSession(ip = ip, isTracing = true) }
        try {
            processManager.execute(
                command = "nmap --traceroute -Pn $ip",
                toolsDir = toolManager.toolsPath,
                workDir = toolManager.corePath,
            ).collect { event ->
                when (event) {
                    is ProcessEvent.StdoutLine -> {
                        parseHop(event.line)?.let { hop ->
                            updateSession(ip) { it.copy(hops = it.hops + hop) }
                        }
                    }
                    is ProcessEvent.StderrLine -> Logger.debug("nmap traceroute stderr: ${event.line}")
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
            updateSession(ip) { it.copy(isTracing = false) }
        }
    }

    private fun parseHop(line: String): TracerouteHop? {
        val hopMatch = HOP_REGEX.find(line) ?: return null
        val hopNumber = hopMatch.groupValues[1].toIntOrNull() ?: return null
        val rest = hopMatch.groupValues[2].trim()

        if (rest == "..." || rest.all { it == '*' || it == ' ' }) {
            return TracerouteHop(hopNumber = hopNumber, rttMs = null, address = null, hostname = null)
        }

        val rttMatch = RTT_ADDR_REGEX.find(rest) ?: return null
        val rtt = rttMatch.groupValues[1].toFloatOrNull()
        val addrPart = rttMatch.groupValues[2].trim()

        val hostIpMatch = HOST_IP_REGEX.find(addrPart)
        return if (hostIpMatch != null) {
            TracerouteHop(
                hopNumber = hopNumber,
                rttMs = rtt,
                address = hostIpMatch.groupValues[2],
                hostname = hostIpMatch.groupValues[1],
            )
        } else {
            TracerouteHop(
                hopNumber = hopNumber,
                rttMs = rtt,
                address = addrPart,
                hostname = null,
            )
        }
    }

    private inline fun updateSession(ip: String, transform: (TracerouteSession) -> TracerouteSession) {
        val current = _sessions.value
        val existing = current[ip] ?: TracerouteSession(ip = ip)
        _sessions.value = current + (ip to transform(existing))
    }
}

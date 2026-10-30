package org.csploit.strix.data

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.csploit.strix.core.Logger
import org.csploit.strix.core.ProcessEvent
import org.csploit.strix.core.ProcessManager
import org.csploit.strix.core.shellQuote
import org.csploit.strix.data.TracerouteHopParser.parseHop
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
    private val nmapDns: NmapDns,
) {
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
                command = "nmap --traceroute -Pn${nmapDns.arg()} ${shellQuote(ip)}",
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
        } catch (ce: CancellationException) {
            throw ce
        } catch (e: Exception) {
            updateSession(ip) { it.copy(error = "Traceroute failed: ${e.message ?: e.javaClass.simpleName}") }
            throw e
        } finally {
            updateSession(ip) { it.copy(isTracing = false) }
        }
    }

    private inline fun updateSession(ip: String, transform: (TracerouteSession) -> TracerouteSession) {
        val current = _sessions.value
        val existing = current[ip] ?: TracerouteSession(ip = ip)
        _sessions.value = current + (ip to transform(existing))
    }
}

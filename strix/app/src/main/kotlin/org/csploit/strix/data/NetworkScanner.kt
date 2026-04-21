package org.csploit.strix.data

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import org.csploit.strix.core.Logger
import org.csploit.strix.core.ProcessEvent
import org.csploit.strix.core.ProcessManager
import javax.inject.Inject
import javax.inject.Singleton

sealed class ScanEvent {
    data class HostFound(val mac: String, val ip: String, val name: String?) : ScanEvent()
    data class HostLost(val ip: String) : ScanEvent()
    data class ScanError(val message: String) : ScanEvent()
    data object ScanEnded : ScanEvent()
}

/**
 * Runs nmap ARP ping scan and parses its output into ScanEvents.
 * Replaces the old network-radar binary with nmap -sn (already bundled).
 *
 * nmap -sn -PR output format (relevant lines):
 *   Nmap scan report for hostname (192.168.1.x)
 *   Host is up (0.0030s latency).
 *   MAC Address: AA:BB:CC:DD:EE:FF (Vendor Name)
 */
@Singleton
class NetworkScanner @Inject constructor(
    private val processManager: ProcessManager,
    private val toolManager: ToolManager,
    private val appSettings: AppSettings,
) {
    companion object {
        // "Nmap scan report for hostname (192.168.1.x)" or "Nmap scan report for 192.168.1.x"
        private val REPORT_REGEX = Regex(
            """Nmap scan report for (?:(\S+)\s+\()?([0-9.]+)\)?"""
        )
        // "MAC Address: AA:BB:CC:DD:EE:FF (Vendor)"
        private val MAC_REGEX = Regex(
            """MAC Address:\s*([0-9A-Fa-f:]+)"""
        )
    }

    fun scan(subnet: String): Flow<ScanEvent> = flow {
        var pendingIp: String? = null
        var pendingName: String? = null

        processManager.execute(
            command = "nmap -sn -PR -T${appSettings.nmapTiming} $subnet",
            toolsDir = toolManager.toolsPath,
            workDir = toolManager.corePath,
        ).collect { event ->
            when (event) {
                is ProcessEvent.StdoutLine -> {
                    REPORT_REGEX.find(event.line)?.let { match ->
                        pendingName = match.groupValues[1].ifEmpty { null }
                        pendingIp = match.groupValues[2]
                    }

                    MAC_REGEX.find(event.line)?.let { match ->
                        val mac = match.groupValues[1]
                        val ip = pendingIp
                        if (ip != null) {
                            emit(ScanEvent.HostFound(mac, ip, pendingName))
                            pendingIp = null
                            pendingName = null
                        }
                    }
                }
                is ProcessEvent.StderrLine -> {
                    Logger.debug("nmap scan stderr: ${event.line}")
                }
                is ProcessEvent.Exited -> {
                    // Emit local host (nmap doesn't show MAC for own IP)
                    if (pendingIp != null) {
                        emit(ScanEvent.HostFound("00:00:00:00:00:00", pendingIp!!, pendingName))
                        pendingIp = null
                    }
                    if (event.code != 0) {
                        emit(ScanEvent.ScanError("nmap scan exited with code ${event.code}"))
                    }
                    emit(ScanEvent.ScanEnded)
                }
                is ProcessEvent.Killed -> {
                    emit(ScanEvent.ScanError("nmap scan killed by signal ${event.signal}"))
                    emit(ScanEvent.ScanEnded)
                }
            }
        }
    }
}

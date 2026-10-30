package org.csploit.strix.data

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.toList
import org.csploit.strix.core.Logger
import org.csploit.strix.core.ProcessEvent
import org.csploit.strix.core.ProcessManager
import org.csploit.strix.core.shellQuote
import javax.inject.Inject
import javax.inject.Singleton

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
    private val nmapDns: NmapDns,
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

    /**
     * Always terminates with [ScanEvent.ScanEnded], also when nmap can't be
     * started or the process flow fails (reported as [ScanEvent.ScanError] first).
     */
    fun scan(subnet: String, interfaceName: String): Flow<ScanEvent> = flow {
        val ownMac = localMac(interfaceName)
        var pendingIp: String? = null
        var pendingName: String? = null
        var ended = false
        var failure: Throwable? = null

        // A report line without a MAC line is the local host (nmap doesn't
        // show a MAC for its own IP): emit it with the interface's MAC.
        suspend fun flushPending() {
            val ip = pendingIp ?: return
            emit(ScanEvent.HostFound(ownMac, ip, pendingName))
            pendingIp = null
            pendingName = null
        }

        processManager.execute(
            command = "nmap -sn -PR -T${appSettings.nmapTiming} --stats-every 10s${nmapDns.arg()} ${shellQuote(subnet)}",
            toolsDir = toolManager.toolsPath,
            workDir = toolManager.corePath,
        ).catch { e ->
            // Upstream only (process start/IO); downstream exceptions are rethrown by catch.
            Logger.error("nmap scan failed: ${e.javaClass.simpleName}: ${e.message}")
            failure = e
        }.collect { event ->
            when (event) {
                is ProcessEvent.StdoutLine -> {
                    Logger.debug("nmap scan stdout: ${event.line}")
                    REPORT_REGEX.find(event.line)?.let { match ->
                        flushPending()
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
                    flushPending()
                    if (event.code != 0) {
                        emit(ScanEvent.ScanError("nmap scan exited with code ${event.code}"))
                    }
                    emit(ScanEvent.ScanEnded)
                    ended = true
                }
                is ProcessEvent.Killed -> {
                    emit(ScanEvent.ScanError("nmap scan killed by signal ${event.signal}"))
                    emit(ScanEvent.ScanEnded)
                    ended = true
                }
            }
        }
        if (!ended) {
            flushPending()
            emit(ScanEvent.ScanError("nmap scan failed: ${failure?.message ?: "no exit status"}"))
            emit(ScanEvent.ScanEnded)
        }
    }

    /**
     * MAC of [iface] as seen on the LAN (the per-network randomized one, if
     * enabled). Apps can't read it since Android 11, root can; placeholder
     * "00:00:00:00:00:00" if unavailable.
     */
    private suspend fun localMac(iface: String): String {
        val out = processManager.execute(command = "cat ${shellQuote("/sys/class/net/$iface/address")}")
            .catch { e -> Logger.warning("cannot read MAC of $iface: ${e.message}") }
            .toList()
        val hex = out.firstNotNullOfOrNull { (it as? ProcessEvent.StdoutLine)?.line }
            ?.let { OuiLookup.normalizeMac(it) }
        return hex?.chunked(2)?.joinToString(":") ?: "00:00:00:00:00:00"
    }
}

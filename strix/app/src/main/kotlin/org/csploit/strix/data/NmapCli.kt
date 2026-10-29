package org.csploit.strix.data

import org.csploit.strix.core.shellQuote
import org.csploit.strix.domain.model.PortInfo

/** nmap command line for [PortScanner] and parsers for its stdout lines. */
internal object NmapCli {
    // Matches: 80/tcp  open  http    Apache httpd 2.4.41
    private val PORT_REGEX = Regex(
        """(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)\s*(.*)"""
    )
    private val OS_REGEX = Regex("""OS details:\s*(.+)""")
    private val PROGRESS_REGEX = Regex("""(\d+\.\d+)% done""")

    /** Throws [IllegalArgumentException] if the effective port range is invalid. */
    fun buildCommand(ip: String, portRange: String?, appSettings: AppSettings): String {
        val range = portRange?.ifBlank { null } ?: appSettings.defaultPortRange.ifBlank { null }
        val portArg = if (range == null) {
            "--top-ports 1000"
        } else {
            "-p " + shellQuote(PortScanner.normalizePortRange(range) ?: throw IllegalArgumentException("Invalid port range '$range'"))
        }
        val timing = appSettings.nmapTiming
        val dnsArg = appSettings.dnsServer.ifBlank { null }?.let { "--dns-servers ${shellQuote(it.trim())}" } ?: ""
        // Custom args are whitespace-separated nmap options: each token is
        // passed as one quoted word so shell metacharacters stay literal.
        val extraArgs = appSettings.customNmapArgs.trim().split(Regex("""\s+"""))
            .filter { it.isNotEmpty() }
            .joinToString(" ") { shellQuote(it) }

        return "nmap -sS -sV -O $portArg -T$timing -Pn $dnsArg $extraArgs ${shellQuote(ip)}"
    }

    fun parsePort(line: String): PortInfo? =
        PORT_REGEX.find(line)?.let { match ->
            PortInfo(
                number = match.groupValues[1].toInt(),
                protocol = match.groupValues[2],
                state = match.groupValues[3],
                service = match.groupValues[4].ifBlank { null },
                version = match.groupValues[5].trim().ifBlank { null },
            )
        }

    fun parseOs(line: String): String? = OS_REGEX.find(line)?.groupValues?.get(1)?.trim()

    fun parseProgress(line: String): String? =
        PROGRESS_REGEX.find(line)?.let { match -> "${match.groupValues[1]}%" }
}

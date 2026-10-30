package org.csploit.strix.data

import org.csploit.strix.core.shellQuote

/** nmap command line for [PortScanner] and parsers for its stdout lines (ports: [NmapPortTable]). */
internal object NmapCli {
    private val OS_REGEX = Regex("""OS details:\s*(.+)""")
    private val PROGRESS_REGEX = Regex("""(\d+\.\d+)% done""")

    /** [dnsArg] comes from [NmapDns.arg]. Throws [IllegalArgumentException] if the effective port range is invalid. */
    fun buildCommand(ip: String, portRange: String?, appSettings: AppSettings, dnsArg: String): String {
        val range = portRange?.ifBlank { null } ?: appSettings.defaultPortRange.ifBlank { null }
        val portArg = if (range == null) {
            "--top-ports 1000"
        } else {
            "-p " + shellQuote(PortScanner.normalizePortRange(range) ?: throw IllegalArgumentException("Invalid port range '$range'"))
        }
        val timing = appSettings.nmapTiming
        // Custom args are whitespace-separated nmap options: each token is
        // passed as one quoted word so shell metacharacters stay literal.
        val extraArgs = appSettings.customNmapArgs.trim().split(Regex("""\s+"""))
            .filter { it.isNotEmpty() }
            .joinToString(" ") { shellQuote(it) }

        return "nmap -sS -sV -O $portArg -T$timing -Pn$dnsArg $extraArgs ${shellQuote(ip)}"
    }

    fun parseOs(line: String): String? = OS_REGEX.find(line)?.groupValues?.get(1)?.trim()

    fun parseProgress(line: String): String? =
        PROGRESS_REGEX.find(line)?.let { match -> "${match.groupValues[1]}%" }
}

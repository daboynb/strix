package org.csploit.strix.data

/**
 * System values captured before the first setup touched them, so cleanup
 * restores the device exactly. Held until cleanup so a second setup (new
 * run, or another host) doesn't overwrite the originals with our values.
 */
internal data class NetSnapshot(
    val iface: String,
    val gateway: String,
    val ipForward: String?,
    val sendRedirectsAll: String?,
    val sendRedirectsIface: String?,
    val forwardPolicy: String?,
    val tetherForwardRules: List<String>,
    val addedDefaultRoute: Boolean,
)

/** Parsers for the `cat`/`iptables -S` output captured into a [NetSnapshot]. */
internal object NetSnapshotParsing {
    fun sysctlValue(raw: String?): String? =
        raw?.trim()?.takeIf { it.all { c -> c.isDigit() } }

    /** Extract the policy from `-P FORWARD ACCEPT` in `iptables -S FORWARD` output. */
    fun parsePolicy(lines: List<String>): String? =
        lines.firstOrNull { it.startsWith("-P FORWARD ") }
            ?.removePrefix("-P FORWARD ")?.trim()?.takeIf { it.isNotEmpty() }

    /**
     * Turn `iptables -S <chain>` output into re-insertable `-A ...` rule bodies,
     * dropping the `-P`/`-N` chain declarations.
     */
    fun parseChainRules(lines: List<String>): List<String> =
        lines.filter { it.startsWith("-A ") }
}

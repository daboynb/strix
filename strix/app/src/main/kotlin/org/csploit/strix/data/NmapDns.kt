package org.csploit.strix.data

import org.csploit.strix.core.shellQuote
import javax.inject.Inject
import javax.inject.Singleton

/**
 * `--dns-servers` for nmap. Android has no /etc/resolv.conf, so without it nmap
 * disables reverse DNS ("Unable to determine any DNS servers") and hosts show
 * no names. Uses the DNS server from Settings if set, else the Wi-Fi's servers.
 */
@Singleton
class NmapDns @Inject constructor(
    private val appSettings: AppSettings,
    private val networkManager: NetworkManager,
) {
    /** The option with a leading space, or "" when no DNS server is known. */
    fun arg(): String = argFor(appSettings.dnsServer, networkManager.wifiDnsServers())

    companion object {
        internal fun argFor(configured: String, wifiServers: List<String>): String {
            val servers = configured.trim().ifEmpty { wifiServers.joinToString(",") }
            return if (servers.isEmpty()) "" else " --dns-servers ${shellQuote(servers)}"
        }
    }
}

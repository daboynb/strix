package org.csploit.strix.ui.navigation

import android.net.Uri

object Routes {
    const val DEEP_LINK_SCHEME = "strix"

    const val SPLASH = "splash"
    const val HOST_LIST = "host_list"
    // Optional (possibly empty) string args are query parameters: an empty
    // value can't be an empty path segment, so the builders omit them and the
    // destination falls back to the navArgument defaultValue. Every value is
    // Uri.encode()d; Navigation decodes path args (Uri.decode) and query args
    // (Uri.getQueryParameters) when matching, so the ViewModels read back the
    // original string.
    const val HOST_DETAIL = "host_detail/{ip}?mac={mac}&name={name}"
    const val PORT_SCANNER = "port_scanner/{ip}"
    const val TRACEROUTE = "traceroute/{ip}"
    const val PACKET_FORGER = "packet_forger/{ip}?mac={mac}"
    const val WIFI_KEYGEN = "wifi_keygen"
    const val SETTINGS = "settings"
    const val LOGS = "logs"
    const val BRUTE_FORCE = "brute_force/{ip}/{port}?service={service}"
    const val MITM = "mitm/{ip}?mac={mac}&mode={mode}"
    const val PACKET_CAPTURE = "packet_capture?ip={ip}"
    const val MSF = "msf"
    const val EXPLOIT_FINDER = "exploit_finder?ip={ip}&port={port}&service={service}"
    const val MSF_SHELL = "msf_shell/{sessionId}"

    private fun seg(value: String): String = Uri.encode(value)

    private fun withQuery(base: String, vararg params: Pair<String, String?>): String {
        val query = params
            .filter { !it.second.isNullOrEmpty() }
            .joinToString("&") { (key, value) -> "$key=${Uri.encode(value)}" }
        return if (query.isEmpty()) base else "$base?$query"
    }

    fun hostDetail(ip: String, mac: String?, name: String?) =
        withQuery("host_detail/${seg(ip)}", "mac" to mac, "name" to name)

    fun portScanner(ip: String) = "port_scanner/${seg(ip)}"
    fun traceroute(ip: String) = "traceroute/${seg(ip)}"
    fun packetForger(ip: String, mac: String) =
        withQuery("packet_forger/${seg(ip)}", "mac" to mac)
    fun mitm(ip: String, mac: String, mode: String = "SNIFFER") =
        withQuery("mitm/${seg(ip)}", "mac" to mac, "mode" to mode)
    fun packetCapture(ip: String) = withQuery("packet_capture", "ip" to ip)

    fun bruteForce(ip: String, port: Int, service: String?) =
        withQuery("brute_force/${seg(ip)}/$port", "service" to service)

    fun exploitFinder(ip: String, port: Int, service: String?) =
        withQuery("exploit_finder", "ip" to ip, "port" to port.toString(), "service" to service)

    fun msfShell(sessionId: Int) = "msf_shell/$sessionId"

    // Deep-link URIs for notification taps. Patterns must match what's declared
    // on each composable via navDeepLink (same shape as the routes above).
    private fun deepLink(route: String): Uri = Uri.parse("$DEEP_LINK_SCHEME://$route")

    fun deepLinkHostList(): Uri = deepLink(HOST_LIST)
    fun deepLinkPortScanner(ip: String): Uri = deepLink(portScanner(ip))
    fun deepLinkBruteForce(ip: String, port: Int, service: String?): Uri =
        deepLink(bruteForce(ip, port, service))
    fun deepLinkMitm(ip: String, mac: String, mode: String): Uri = deepLink(mitm(ip, mac, mode))
    fun deepLinkPacketCapture(ip: String): Uri = deepLink(packetCapture(ip))
    fun deepLinkTraceroute(ip: String): Uri = deepLink(traceroute(ip))
    fun deepLinkMsfShell(sessionId: Int): Uri = deepLink(msfShell(sessionId))

    fun deepLinkPattern(route: String): String = "$DEEP_LINK_SCHEME://$route"
}

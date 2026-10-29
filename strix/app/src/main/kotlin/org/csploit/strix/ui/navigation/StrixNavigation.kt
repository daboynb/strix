package org.csploit.strix.ui.navigation

import android.content.Intent
import android.net.Uri
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import androidx.navigation.navDeepLink
import androidx.navigation.navOptions
import kotlinx.coroutines.flow.StateFlow
import org.csploit.strix.ui.bruteforce.BruteForceScreen
import org.csploit.strix.ui.hostdetail.HostDetailScreen
import org.csploit.strix.ui.hostlist.HostListScreen
import org.csploit.strix.ui.logs.LogsScreen
import org.csploit.strix.ui.mitm.MitmScreen
import org.csploit.strix.ui.msf.ExploitFinderScreen
import org.csploit.strix.ui.msf.MsfScreen
import org.csploit.strix.ui.msf.ShellScreen
import org.csploit.strix.ui.packetcapture.PacketCaptureScreen
import org.csploit.strix.ui.packetforger.PacketForgerScreen
import org.csploit.strix.ui.portscan.PortScannerScreen
import org.csploit.strix.ui.splash.SplashScreen
import org.csploit.strix.ui.traceroute.TracerouteScreen
import org.csploit.strix.ui.settings.SettingsScreen
import org.csploit.strix.ui.wifikeygen.WifiKeygenScreen

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

    fun hostDetail(ip: String, mac: String, name: String?) =
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

@Composable
fun StrixNavigation(intentFlow: StateFlow<Intent?>? = null) {
    val navController = rememberNavController()

    // Deep links that arrive AFTER splash completes (onNewIntent): navigate
    // straight to the destination via the deep-link Uri. We don't use
    // handleDeepLink() because it rebuilds the full backstack from the start
    // destination, which re-creates the SPLASH entry and its side-effects would
    // then navigate away again and clear our target. A plain navigate(uri) just
    // pushes the target on top of the current stack.
    //
    // Deep links delivered AT launch (intent already set in onCreate) are
    // consumed below in the splash's onStartupComplete so the splash's
    // popUpTo(SPLASH){inclusive} doesn't wipe them out.
    if (intentFlow != null) {
        val latestIntent by intentFlow.collectAsStateWithLifecycle()
        LaunchedEffect(latestIntent) {
            val data = latestIntent?.data ?: return@LaunchedEffect
            val currentRoute = navController.currentBackStackEntry?.destination?.route
            if (currentRoute != null && currentRoute != Routes.SPLASH) {
                runCatching { navController.navigate(data) }
            }
        }
    }

    NavHost(navController = navController, startDestination = Routes.SPLASH) {
        composable(Routes.SPLASH) {
            SplashScreen(
                onStartupComplete = {
                    val pendingDeepLink = intentFlow?.value?.data
                    // navigate(Uri, NavOptions) explicitly: a trailing-lambda
                    // call would resolve to the type-safe navigate<T>(route: T)
                    // overload and try to serialize the Uri. A stale
                    // notification may carry a URI from an older route shape:
                    // navigate(Uri) throws if nothing matches, so fall back to
                    // the host list instead of crashing.
                    val handled = pendingDeepLink != null && runCatching {
                        navController.navigate(
                            pendingDeepLink,
                            navOptions { popUpTo(Routes.SPLASH) { inclusive = true } },
                        )
                    }.isSuccess
                    if (!handled) {
                        navController.navigate(Routes.HOST_LIST) {
                            popUpTo(Routes.SPLASH) { inclusive = true }
                        }
                    }
                },
            )
        }
        composable(
            Routes.HOST_LIST,
            deepLinks = listOf(navDeepLink { uriPattern = Routes.deepLinkPattern(Routes.HOST_LIST) }),
        ) {
            HostListScreen(
                onHostClick = { host, _ ->
                    navController.navigate(Routes.hostDetail(host.ip, host.mac, host.name))
                },
                onWifiKeygen = {
                    navController.navigate(Routes.WIFI_KEYGEN)
                },
                onMsf = {
                    navController.navigate(Routes.MSF)
                },
                onSettings = {
                    navController.navigate(Routes.SETTINGS)
                },
                onLogs = {
                    navController.navigate(Routes.LOGS)
                },
            )
        }
        composable(
            Routes.HOST_DETAIL,
            arguments = listOf(
                navArgument("ip") { type = NavType.StringType },
                navArgument("mac") { type = NavType.StringType; defaultValue = "" },
                navArgument("name") { type = NavType.StringType; defaultValue = "" },
            ),
        ) {
            val mac = it.arguments?.getString("mac") ?: ""
            HostDetailScreen(
                onBack = { navController.popBackStack() },
                onPortScanner = { ip ->
                    navController.navigate(Routes.portScanner(ip))
                },
                onTraceroute = { ip ->
                    navController.navigate(Routes.traceroute(ip))
                },
                onPacketForger = { ip ->
                    navController.navigate(Routes.packetForger(ip, mac))
                },
                onMitmSniffer = { ip ->
                    navController.navigate(Routes.mitm(ip, mac, "SNIFFER"))
                },
                onMitmDnsSpoof = { ip ->
                    navController.navigate(Routes.mitm(ip, mac, "DNS_SPOOF"))
                },
                onMitmKill = { ip ->
                    navController.navigate(Routes.mitm(ip, mac, "KILL"))
                },
                onPacketCapture = { ip ->
                    navController.navigate(Routes.packetCapture(ip))
                },
            )
        }
        composable(
            Routes.PORT_SCANNER,
            arguments = listOf(
                navArgument("ip") { type = NavType.StringType },
            ),
            deepLinks = listOf(navDeepLink { uriPattern = Routes.deepLinkPattern(Routes.PORT_SCANNER) }),
        ) {
            PortScannerScreen(
                onBack = { navController.popBackStack() },
                onBruteForce = { ip, port, service ->
                    navController.navigate(Routes.bruteForce(ip, port, service))
                },
                onExploitFinder = { ip, port, service ->
                    navController.navigate(Routes.exploitFinder(ip, port, service))
                },
            )
        }
        composable(
            Routes.PACKET_FORGER,
            arguments = listOf(
                navArgument("ip") { type = NavType.StringType },
                navArgument("mac") { type = NavType.StringType; defaultValue = "" },
            ),
        ) {
            PacketForgerScreen(onBack = { navController.popBackStack() })
        }
        composable(
            Routes.TRACEROUTE,
            arguments = listOf(
                navArgument("ip") { type = NavType.StringType },
            ),
            deepLinks = listOf(navDeepLink { uriPattern = Routes.deepLinkPattern(Routes.TRACEROUTE) }),
        ) {
            TracerouteScreen(onBack = { navController.popBackStack() })
        }
        composable(Routes.WIFI_KEYGEN) {
            WifiKeygenScreen(onBack = { navController.popBackStack() })
        }
        composable(Routes.SETTINGS) {
            SettingsScreen(
                onBack = { navController.popBackStack() },
                onLogs = { navController.navigate(Routes.LOGS) },
            )
        }
        composable(Routes.LOGS) {
            LogsScreen(onBack = { navController.popBackStack() })
        }
        composable(
            Routes.PACKET_CAPTURE,
            arguments = listOf(
                navArgument("ip") { type = NavType.StringType; defaultValue = "" },
            ),
            deepLinks = listOf(navDeepLink { uriPattern = Routes.deepLinkPattern(Routes.PACKET_CAPTURE) }),
        ) {
            PacketCaptureScreen(onBack = { navController.popBackStack() })
        }
        composable(
            Routes.MITM,
            arguments = listOf(
                navArgument("ip") { type = NavType.StringType },
                navArgument("mac") { type = NavType.StringType; defaultValue = "" },
                navArgument("mode") { type = NavType.StringType; defaultValue = "SNIFFER" },
            ),
            deepLinks = listOf(navDeepLink { uriPattern = Routes.deepLinkPattern(Routes.MITM) }),
        ) {
            MitmScreen(onBack = { navController.popBackStack() })
        }
        composable(
            Routes.BRUTE_FORCE,
            arguments = listOf(
                navArgument("ip") { type = NavType.StringType },
                navArgument("port") { type = NavType.StringType },
                navArgument("service") { type = NavType.StringType; defaultValue = "unknown" },
            ),
            deepLinks = listOf(navDeepLink { uriPattern = Routes.deepLinkPattern(Routes.BRUTE_FORCE) }),
        ) {
            BruteForceScreen(onBack = { navController.popBackStack() })
        }
        composable(
            Routes.MSF,
            deepLinks = listOf(navDeepLink { uriPattern = Routes.deepLinkPattern(Routes.MSF) }),
        ) {
            MsfScreen(
                onBack = { navController.popBackStack() },
                onExploitFinder = {
                    navController.navigate(Routes.exploitFinder("", 0, null))
                },
                onShell = { sessionId ->
                    navController.navigate(Routes.msfShell(sessionId))
                },
            )
        }
        composable(
            Routes.EXPLOIT_FINDER,
            arguments = listOf(
                navArgument("ip") { type = NavType.StringType; defaultValue = "" },
                navArgument("port") { type = NavType.StringType; defaultValue = "0" },
                navArgument("service") { type = NavType.StringType; defaultValue = "unknown" },
            ),
        ) {
            ExploitFinderScreen(
                onBack = { navController.popBackStack() },
                onOpenMsf = {
                    navController.navigate(Routes.MSF) {
                        popUpTo(Routes.EXPLOIT_FINDER) { inclusive = true }
                    }
                },
                onShell = { sessionId ->
                    navController.navigate(Routes.msfShell(sessionId))
                },
            )
        }
        composable(
            Routes.MSF_SHELL,
            arguments = listOf(
                navArgument("sessionId") { type = NavType.IntType },
            ),
            deepLinks = listOf(navDeepLink { uriPattern = Routes.deepLinkPattern(Routes.MSF_SHELL) }),
        ) {
            ShellScreen(onBack = { navController.popBackStack() })
        }
    }
}


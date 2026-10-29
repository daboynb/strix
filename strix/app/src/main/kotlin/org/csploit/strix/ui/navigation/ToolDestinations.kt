package org.csploit.strix.ui.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import androidx.navigation.navDeepLink
import org.csploit.strix.ui.bruteforce.BruteForceScreen
import org.csploit.strix.ui.logs.LogsScreen
import org.csploit.strix.ui.mitm.MitmScreen
import org.csploit.strix.ui.packetcapture.PacketCaptureScreen
import org.csploit.strix.ui.packetforger.PacketForgerScreen
import org.csploit.strix.ui.portscan.PortScannerScreen
import org.csploit.strix.ui.settings.SettingsScreen
import org.csploit.strix.ui.traceroute.TracerouteScreen
import org.csploit.strix.ui.wifikeygen.WifiKeygenScreen

/** Per-host tools plus the global utility screens (keygen, settings, logs). */
internal fun NavGraphBuilder.toolDestinations(navController: NavHostController) {
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
}

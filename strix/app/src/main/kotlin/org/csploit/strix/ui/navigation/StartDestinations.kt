package org.csploit.strix.ui.navigation

import android.content.Intent
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import androidx.navigation.navDeepLink
import androidx.navigation.navOptions
import kotlinx.coroutines.flow.StateFlow
import org.csploit.strix.ui.hostdetail.HostDetailScreen
import org.csploit.strix.ui.hostlist.HostListScreen
import org.csploit.strix.ui.splash.SplashScreen

/** Splash, host list and host detail: the entry flow of the app. */
internal fun NavGraphBuilder.startDestinations(
    navController: NavHostController,
    intentFlow: StateFlow<Intent?>?,
) {
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
}

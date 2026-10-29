package org.csploit.strix.ui.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import androidx.navigation.navDeepLink
import org.csploit.strix.ui.msf.ExploitFinderScreen
import org.csploit.strix.ui.msf.MsfScreen
import org.csploit.strix.ui.msf.ShellScreen

/** Metasploit console, exploit finder and session shell. */
internal fun NavGraphBuilder.msfDestinations(navController: NavHostController) {
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

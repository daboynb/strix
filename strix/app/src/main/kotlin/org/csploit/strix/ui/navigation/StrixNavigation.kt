package org.csploit.strix.ui.navigation

import android.content.Intent
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.rememberNavController
import kotlinx.coroutines.flow.StateFlow

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
        startDestinations(navController, intentFlow)
        toolDestinations(navController)
        msfDestinations(navController)
    }
}

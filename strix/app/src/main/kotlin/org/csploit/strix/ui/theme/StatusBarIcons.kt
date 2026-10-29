package org.csploit.strix.ui.theme

import android.app.Activity
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

/**
 * Picks dark or light status bar icons for the color drawn behind them.
 * With edge-to-edge the top app bar sits under the status bar, and some
 * dynamic palettes (e.g. HyperOS) give a light primaryContainer in dark mode.
 */
@Composable
fun StatusBarIcons(background: Color) {
    val view = LocalView.current
    if (view.isInEditMode) return
    val lightBackground = background.luminance() > 0.5f
    SideEffect {
        val window = (view.context as? Activity)?.window ?: return@SideEffect
        WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = lightBackground
    }
}

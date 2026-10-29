package org.csploit.strix

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.flow.MutableStateFlow
import org.csploit.strix.ui.navigation.StrixNavigation
import org.csploit.strix.ui.theme.FangTheme

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    private val intentFlow = MutableStateFlow<Intent?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        // Runtime permissions (incl. POST_NOTIFICATIONS) are requested in one
        // batch by SplashScreen: a separate request here would still be pending
        // when the splash asks for location, and the second request is dropped.
        intentFlow.value = intent
        setContent {
            FangTheme {
                StrixNavigation(intentFlow = intentFlow)
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        intentFlow.value = intent
    }
}

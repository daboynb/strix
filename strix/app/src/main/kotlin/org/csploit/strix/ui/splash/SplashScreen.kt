package org.csploit.strix.ui.splash

import android.Manifest
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

@Composable
fun SplashScreen(
    onStartupComplete: () -> Unit,
    viewModel: SplashViewModel = hiltViewModel(),
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    // Navigate when ready
    LaunchedEffect(uiState.step) {
        if (uiState.step == StartupStep.READY) {
            onStartupComplete()
        }
    }

    // Permission launcher
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { grants ->
        // Proceed regardless — we need location for SSID but app can work without it
        viewModel.onPermissionsGranted()
    }

    // Single batched request on first composition: notification, location and
    // nearby-Wi-Fi together (MainActivity no longer issues its own request,
    // which used to make this one get dropped). Saveable so a configuration
    // change doesn't fire a second request while the dialog is showing.
    var permissionsRequested by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        if (permissionsRequested) return@LaunchedEffect
        permissionsRequested = true
        val permissions = buildList {
            // targetSdk 31+: FINE must be requested together with COARSE,
            // otherwise the system ignores the request.
            add(Manifest.permission.ACCESS_FINE_LOCATION)
            add(Manifest.permission.ACCESS_COARSE_LOCATION)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                add(Manifest.permission.POST_NOTIFICATIONS)
                add(Manifest.permission.NEARBY_WIFI_DEVICES)
            }
        }
        permissionLauncher.launch(permissions.toTypedArray())
    }

    Scaffold { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            SplashStepContent(uiState, onRetry = { viewModel.onPermissionsGranted() })
        }
    }
}

package org.csploit.strix.ui.splash

import android.Manifest
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.csploit.strix.domain.model.ExtractionState

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

    // Request permissions on first composition
    LaunchedEffect(Unit) {
        val permissions = buildList {
            add(Manifest.permission.ACCESS_FINE_LOCATION)
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
            when (uiState.step) {
                StartupStep.WAITING_PERMISSIONS -> {
                    Icon(
                        imageVector = Icons.Default.Security,
                        contentDescription = null,
                        modifier = Modifier.size(64.dp),
                        tint = MaterialTheme.colorScheme.primary,
                    )
                    Spacer(Modifier.height(16.dp))
                    Text("Requesting permissions...", style = MaterialTheme.typography.titleMedium)
                }

                StartupStep.CHECKING_ROOT -> {
                    CircularProgressIndicator()
                    Spacer(Modifier.height(16.dp))
                    Text("Checking root access...", style = MaterialTheme.typography.titleMedium)
                }

                StartupStep.EXTRACTING_TOOLS -> {
                    val extraction = uiState.extractionState
                    CircularProgressIndicator()
                    Spacer(Modifier.height(16.dp))
                    Text("Extracting tools...", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(8.dp))
                    when (extraction) {
                        is ExtractionState.Extracting -> {
                            LinearProgressIndicator(modifier = Modifier.padding(horizontal = 32.dp))
                            Spacer(Modifier.height(4.dp))
                            Text(
                                "${extraction.filesExtracted} files extracted",
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                        is ExtractionState.PatchingConfig -> {
                            Text("Patching configuration...", style = MaterialTheme.typography.bodySmall)
                        }
                        is ExtractionState.AlreadyInstalled -> {
                            Text("Tools already installed", style = MaterialTheme.typography.bodySmall)
                        }
                        else -> {}
                    }
                }

                StartupStep.DETECTING_NETWORK -> {
                    CircularProgressIndicator()
                    Spacer(Modifier.height(16.dp))
                    Text("Detecting WiFi network...", style = MaterialTheme.typography.titleMedium)
                }

                StartupStep.READY -> {
                    // Will navigate away
                    CircularProgressIndicator()
                }

                StartupStep.FAILED -> {
                    Icon(
                        imageVector = Icons.Default.Error,
                        contentDescription = null,
                        modifier = Modifier.size(64.dp),
                        tint = MaterialTheme.colorScheme.error,
                    )
                    Spacer(Modifier.height(16.dp))
                    Text(
                        uiState.error ?: "Unknown error",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.error,
                        textAlign = TextAlign.Center,
                    )
                    Spacer(Modifier.height(24.dp))
                    Button(onClick = { viewModel.onPermissionsGranted() }) {
                        Text("Retry")
                    }
                }
            }
        }
    }
}

package org.csploit.strix.ui.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.csploit.strix.ui.theme.StatusBarIcons

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onBack: () -> Unit,
    onLogs: () -> Unit = {},
    viewModel: SettingsViewModel = hiltViewModel(),
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val msfBundle by viewModel.msfBundleState.collectAsStateWithLifecycle()
    val toolsBundle by viewModel.toolsBundleState.collectAsStateWithLifecycle()
    val checkingUpdates by viewModel.checkingUpdates.collectAsStateWithLifecycle()

    Scaffold(
        topBar = {
            StatusBarIcons(MaterialTheme.colorScheme.primaryContainer)
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                    navigationIconContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                    actionIconContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                ),
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            ScanSettingsSections(uiState, viewModel)

            HorizontalDivider()

            SectionHeader("Bundles")

            BundlesSection(
                uiState = uiState,
                tools = toolsBundle,
                msf = msfBundle,
                checking = checkingUpdates,
                onCheck = viewModel::checkForUpdates,
                onWifiOnly = viewModel::setBundleWifiOnly,
                onReinstallTools = viewModel::reinstallTools,
                onDownloadTools = viewModel::downloadTools,
                onCancelTools = viewModel::cancelTools,
                onApplyTools = viewModel::applyPendingTools,
                onDismissTools = viewModel::dismissToolsMessage,
                onDismissMessages = viewModel::dismissBundleMessages,
            )

            HorizontalDivider()

            SectionHeader("Diagnostics")

            Text(
                "App log (also crashes) for bug reports. Share redacts Wi-Fi SSID/BSSID.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedButton(onClick = onLogs, modifier = Modifier.fillMaxWidth()) {
                Text("View logs")
            }
        }
    }
}

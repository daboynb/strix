package org.csploit.strix.ui.msf

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import org.csploit.strix.ui.bundles.BundleUpdateCard
import org.csploit.strix.ui.theme.StatusBarIcons

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MsfScreen(
    onBack: () -> Unit,
    onExploitFinder: () -> Unit = {},
    onShell: (Int) -> Unit = {},
    viewModel: MsfViewModel = hiltViewModel(),
) {
    val uiState by viewModel.uiState.collectAsState()
    val daemonState by viewModel.daemonState.collectAsState()
    val logs by viewModel.daemonLogs.collectAsState()
    val bundleState by viewModel.bundleState.collectAsState()

    Scaffold(
        topBar = {
            StatusBarIcons(MaterialTheme.colorScheme.surface)
            TopAppBar(
                title = { Text("Metasploit") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                ),
            )
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // Download / update of the Metasploit bundle
            item {
                BundleUpdateCard(
                    state = bundleState,
                    notInstalledHint = "Metasploit is downloaded separately from the app (≈375 MB, needs ≈1.3 GB free while installing).",
                    onDownload = viewModel::downloadMsf,
                    onCancel = viewModel::cancelBundleOp,
                    onApply = viewModel::applyPendingUpdate,
                    onDismiss = viewModel::dismissBundleMessage,
                )
            }

            // Status Card
            item {
                DaemonStatusCard(
                    daemonState = daemonState,
                    msfInstalled = uiState.msfInstalled,
                    isConnected = uiState.isConnected,
                    connecting = uiState.connecting,
                    msfVersion = uiState.msfVersion,
                    onStart = viewModel::startDaemon,
                    onStop = viewModel::stopDaemon,
                    onConnect = viewModel::connectToRpc,
                )
            }

            // Error
            uiState.error?.let { error ->
                item {
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.errorContainer,
                        ),
                    ) {
                        Text(
                            error,
                            modifier = Modifier.padding(12.dp),
                            color = MaterialTheme.colorScheme.onErrorContainer,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }

            // Actions (only when connected)
            if (uiState.isConnected) {
                item {
                    MsfActionsCard(onExploitFinder)
                }

                // Sessions
                item {
                    SessionsHeader(uiState.sessions.size, onRefresh = viewModel::refreshSessions)
                }

                if (uiState.sessions.isEmpty()) {
                    item {
                        Text(
                            "No active sessions",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }

                items(uiState.sessions, key = { it.id }) { session ->
                    SessionCard(
                        session = session,
                        onShell = { onShell(session.id) },
                        onStop = { viewModel.stopSession(session.id) },
                    )
                }
            }

            // Daemon Logs
            if (logs.isNotEmpty()) {
                item {
                    Text("Daemon Log", style = MaterialTheme.typography.titleMedium)
                }
                item {
                    DaemonLogCard(logs)
                }
            }
        }
    }
}

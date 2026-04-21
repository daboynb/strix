package org.csploit.strix.ui.msf

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.CloudOff
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import org.csploit.strix.data.DaemonState

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

    Scaffold(
        topBar = {
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
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text("Actions", style = MaterialTheme.typography.titleMedium)
                            Spacer(Modifier.height(8.dp))
                            Button(
                                onClick = onExploitFinder,
                                modifier = Modifier.fillMaxWidth(),
                            ) {
                                Icon(Icons.Default.Terminal, null, Modifier.size(18.dp))
                                Spacer(Modifier.width(8.dp))
                                Text("Exploit Finder")
                            }
                        }
                    }
                }

                // Sessions
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            "Sessions (${uiState.sessions.size})",
                            style = MaterialTheme.typography.titleMedium,
                        )
                        IconButton(onClick = viewModel::refreshSessions) {
                            Icon(Icons.Default.Refresh, "Refresh")
                        }
                    }
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

@Composable
private fun DaemonStatusCard(
    daemonState: DaemonState,
    msfInstalled: Boolean,
    isConnected: Boolean,
    connecting: Boolean,
    msfVersion: String?,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onConnect: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    if (isConnected) Icons.Default.Cloud else Icons.Default.CloudOff,
                    null,
                    tint = when {
                        isConnected -> MaterialTheme.colorScheme.primary
                        daemonState == DaemonState.READY -> MaterialTheme.colorScheme.tertiary
                        else -> MaterialTheme.colorScheme.onSurfaceVariant
                    },
                )
                Spacer(Modifier.width(12.dp))
                Column {
                    Text(
                        when {
                            isConnected -> "Connected"
                            daemonState == DaemonState.READY -> "Daemon ready, not connected"
                            daemonState == DaemonState.STARTING -> "Starting daemon..."
                            daemonState == DaemonState.FAILED -> "Daemon failed"
                            !msfInstalled -> "MSF not installed"
                            else -> "Daemon stopped"
                        },
                        style = MaterialTheme.typography.titleSmall,
                    )
                    msfVersion?.let {
                        Text(
                            "MSF $it",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }

            Spacer(Modifier.height(12.dp))

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                when {
                    daemonState == DaemonState.STARTING || connecting -> {
                        CircularProgressIndicator(modifier = Modifier.size(36.dp))
                    }
                    daemonState == DaemonState.STOPPED || daemonState == DaemonState.FAILED -> {
                        Button(
                            onClick = onStart,
                            enabled = msfInstalled,
                        ) {
                            Icon(Icons.Default.PlayArrow, null, Modifier.size(18.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("Start Daemon")
                        }
                        OutlinedButton(onClick = onConnect) {
                            Text("Connect Remote")
                        }
                    }
                    daemonState == DaemonState.READY && !isConnected -> {
                        Button(onClick = onConnect) {
                            Text("Connect")
                        }
                        OutlinedButton(
                            onClick = onStop,
                            colors = ButtonDefaults.outlinedButtonColors(
                                contentColor = MaterialTheme.colorScheme.error,
                            ),
                        ) {
                            Icon(Icons.Default.Stop, null, Modifier.size(18.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("Stop")
                        }
                    }
                    isConnected -> {
                        OutlinedButton(
                            onClick = onStop,
                            colors = ButtonDefaults.outlinedButtonColors(
                                contentColor = MaterialTheme.colorScheme.error,
                            ),
                        ) {
                            Icon(Icons.Default.Stop, null, Modifier.size(18.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("Disconnect & Stop")
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SessionCard(
    session: org.csploit.strix.domain.model.MsfSession,
    onShell: () -> Unit,
    onStop: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    "#${session.id} ${session.type}",
                    style = MaterialTheme.typography.titleSmall,
                )
                Text(
                    "${session.targetHost}:${session.targetPort}",
                    style = MaterialTheme.typography.bodySmall,
                )
                if (session.viaExploit.isNotEmpty()) {
                    Text(
                        session.viaExploit.substringAfterLast('/'),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            if (session.type == "shell" || session.type == "meterpreter") {
                IconButton(onClick = onShell) {
                    Icon(Icons.Default.Terminal, "Shell")
                }
            }
            IconButton(onClick = onStop) {
                Icon(Icons.Default.Delete, "Stop", tint = MaterialTheme.colorScheme.error)
            }
        }
    }
}

@Composable
private fun DaemonLogCard(logs: List<String>) {
    val listState = rememberLazyListState()

    LaunchedEffect(logs.size) {
        if (logs.isNotEmpty()) {
            listState.animateScrollToItem(logs.size - 1)
        }
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .height(200.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant,
        ),
    ) {
        LazyColumn(
            state = listState,
            modifier = Modifier.padding(8.dp),
        ) {
            items(logs) { line ->
                Text(
                    line,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 10.sp,
                    lineHeight = 14.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

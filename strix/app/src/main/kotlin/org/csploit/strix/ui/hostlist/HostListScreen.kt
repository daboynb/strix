package org.csploit.strix.ui.hostlist

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Computer
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Router
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.csploit.strix.domain.model.Host

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HostListScreen(
    onHostClick: (Host, Boolean) -> Unit = { _, _ -> },
    onWifiKeygen: () -> Unit = {},
    onMsf: () -> Unit = {},
    onSettings: () -> Unit = {},
    viewModel: HostListViewModel = hiltViewModel(),
) {
    val hosts by viewModel.hosts.collectAsStateWithLifecycle()
    val networkInfo by viewModel.networkInfo.collectAsStateWithLifecycle()
    val isScanning by viewModel.isScanning.collectAsStateWithLifecycle()
    val error by viewModel.error.collectAsStateWithLifecycle()

    var showAddDialog by remember { mutableStateOf(false) }

    if (showAddDialog) {
        AddHostDialog(
            onDismiss = { showAddDialog = false },
            onAdd = { ip, name ->
                viewModel.addManualHost(ip, name)
                showAddDialog = false
            },
        )
    }

    Scaffold(
        floatingActionButton = {
            FloatingActionButton(onClick = { showAddDialog = true }) {
                Icon(Icons.Default.Add, contentDescription = "Add host")
            }
        },
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("Strix")
                        networkInfo?.let {
                            Text(
                                "${it.ssid} - ${it.localIp}/${it.prefixLength}",
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    }
                },
                actions = {
                    IconButton(onClick = onMsf) {
                        Icon(Icons.Default.Security, contentDescription = "Metasploit")
                    }
                    IconButton(onClick = onSettings) {
                        Icon(Icons.Default.Settings, contentDescription = "Settings")
                    }
                    IconButton(onClick = onWifiKeygen) {
                        Icon(Icons.Default.Wifi, contentDescription = "WiFi Keygen")
                    }
                    if (isScanning) {
                        IconButton(onClick = { viewModel.stopScan() }) {
                            Icon(Icons.Default.Stop, contentDescription = "Stop scan")
                        }
                    } else {
                        IconButton(onClick = { viewModel.startScan() }) {
                            Icon(Icons.Default.PlayArrow, contentDescription = "Start scan")
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                ),
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            if (isScanning) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }

            error?.let {
                Text(
                    it,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(16.dp),
                )
            }

            if (hosts.isEmpty() && !isScanning) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center,
                ) {
                    Text("No hosts discovered", style = MaterialTheme.typography.bodyLarge)
                }
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    items(hosts, key = { it.ip }) { host ->
                        val isGateway = host.ip == networkInfo?.gatewayIp
                        val isSelf = host.ip == networkInfo?.localIp
                        HostCard(
                            host = host,
                            isGateway = isGateway,
                            isSelf = isSelf,
                            onClick = { onHostClick(host, isGateway) },
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun HostCard(
    host: Host,
    isGateway: Boolean,
    isSelf: Boolean,
    onClick: () -> Unit = {},
) {
    val isManual = host.mac == "manual"
    val icon: ImageVector
    val label: String

    when {
        isGateway -> {
            icon = Icons.Default.Router
            label = "Gateway"
        }
        isSelf -> {
            icon = Icons.Default.PhoneAndroid
            label = "This device"
        }
        isManual -> {
            icon = Icons.Default.Language
            label = host.name ?: host.ip
        }
        else -> {
            icon = Icons.Default.Computer
            label = host.name ?: ""
        }
    }

    val alpha = if (host.connected) 1f else 0.5f

    Card(
        onClick = onClick,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp, vertical = 2.dp),
        colors = CardDefaults.cardColors(
            containerColor = when {
                isGateway -> MaterialTheme.colorScheme.secondaryContainer
                isSelf -> MaterialTheme.colorScheme.tertiaryContainer
                else -> MaterialTheme.colorScheme.surfaceVariant
            },
        ),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = icon,
                contentDescription = label,
                modifier = Modifier.size(32.dp),
                tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = alpha),
            )
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = if (label.isNotEmpty()) label else host.ip,
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = alpha),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = host.ip,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = alpha),
                )
                if (!isManual) {
                    Text(
                        text = host.mac,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = alpha * 0.7f),
                    )
                }
            }
            if (!host.connected) {
                Icon(
                    imageVector = Icons.Default.Wifi,
                    contentDescription = "Disconnected",
                    modifier = Modifier.size(16.dp),
                    tint = MaterialTheme.colorScheme.error.copy(alpha = 0.6f),
                )
            }
        }
    }
}

@Composable
private fun AddHostDialog(
    onDismiss: () -> Unit,
    onAdd: (ip: String, name: String?) -> Unit,
) {
    var ip by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    val ipValid = ip.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")) ||
        ip.matches(Regex("^[a-zA-Z0-9][a-zA-Z0-9._-]*\\.[a-zA-Z]{2,}$"))

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Add Target") },
        text = {
            Column {
                OutlinedTextField(
                    value = ip,
                    onValueChange = { ip = it.trim() },
                    label = { Text("IP or hostname") },
                    singleLine = true,
                    isError = ip.isNotEmpty() && !ipValid,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Label (optional)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onAdd(ip, name.ifBlank { null }) },
                enabled = ipValid,
            ) { Text("Add") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

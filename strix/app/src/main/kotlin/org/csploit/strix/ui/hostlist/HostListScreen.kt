package org.csploit.strix.ui.hostlist

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.csploit.strix.domain.model.Host

@Composable
fun HostListScreen(
    onHostClick: (Host, Boolean) -> Unit = { _, _ -> },
    onWifiKeygen: () -> Unit = {},
    onMsf: () -> Unit = {},
    onSettings: () -> Unit = {},
    onLogs: () -> Unit = {},
    viewModel: HostListViewModel = hiltViewModel(),
) {
    val hosts by viewModel.hosts.collectAsStateWithLifecycle()
    val networkInfo by viewModel.networkInfo.collectAsStateWithLifecycle()
    val isScanning by viewModel.isScanning.collectAsStateWithLifecycle()
    val error by viewModel.error.collectAsStateWithLifecycle()
    val bundleUpdate by viewModel.bundleUpdateBanner.collectAsStateWithLifecycle()

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
            HostListTopBar(
                networkInfo = networkInfo,
                isScanning = isScanning,
                onMsf = onMsf,
                onSettings = onSettings,
                onStartScan = { viewModel.startScan() },
                onStopScan = { viewModel.stopScan() },
                onWifiKeygen = onWifiKeygen,
                onLogs = onLogs,
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

            bundleUpdate?.let { versions ->
                BundleUpdateCard(versions, onClick = onSettings)
            }

            HostListContent(hosts, networkInfo, isScanning, onHostClick)
        }
    }
}

package org.csploit.strix.ui.hostlist

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import org.csploit.strix.domain.model.NetworkInfo
import org.csploit.strix.ui.theme.StatusBarIcons

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun HostListTopBar(
    networkInfo: NetworkInfo?,
    isScanning: Boolean,
    onMsf: () -> Unit,
    onSettings: () -> Unit,
    onStartScan: () -> Unit,
    onStopScan: () -> Unit,
    onWifiKeygen: () -> Unit,
    onLogs: () -> Unit,
) {
    var showMenu by remember { mutableStateOf(false) }

    StatusBarIcons(MaterialTheme.colorScheme.primaryContainer)
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
            if (isScanning) {
                IconButton(onClick = onStopScan) {
                    Icon(Icons.Default.Stop, contentDescription = "Stop scan")
                }
            } else {
                IconButton(onClick = onStartScan) {
                    Icon(Icons.Default.PlayArrow, contentDescription = "Start scan")
                }
            }
            // WiFi Keygen lives here: five icons left too little room for the SSID/IP subtitle.
            Box {
                IconButton(onClick = { showMenu = true }) {
                    Icon(Icons.Default.MoreVert, contentDescription = "More options")
                }
                DropdownMenu(expanded = showMenu, onDismissRequest = { showMenu = false }) {
                    DropdownMenuItem(
                        text = { Text("WiFi Keygen") },
                        leadingIcon = { Icon(Icons.Default.Wifi, contentDescription = null) },
                        onClick = { showMenu = false; onWifiKeygen() },
                    )
                    DropdownMenuItem(
                        text = { Text("Logs") },
                        leadingIcon = { Icon(Icons.Default.Description, contentDescription = null) },
                        onClick = { showMenu = false; onLogs() },
                    )
                }
            }
        },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer,
            titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
            navigationIconContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
            actionIconContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
        ),
    )
}

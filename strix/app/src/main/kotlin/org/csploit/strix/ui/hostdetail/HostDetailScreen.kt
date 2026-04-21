package org.csploit.strix.ui.hostdetail

import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.AltRoute
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.automirrored.filled.Send
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel

data class ActionItem(
    val icon: ImageVector,
    val label: String,
    val enabled: Boolean = true,
    val onClick: () -> Unit,
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HostDetailScreen(
    onBack: () -> Unit,
    onPortScanner: (String) -> Unit = {},
    onTraceroute: (String) -> Unit = {},
    onPacketForger: (String) -> Unit = {},
    onMitmSniffer: (String) -> Unit = {},
    onMitmDnsSpoof: (String) -> Unit = {},
    onMitmKill: (String) -> Unit = {},
    onPacketCapture: (String) -> Unit = {},
    onBruteForce: (String, Int, String?) -> Unit = { _, _, _ -> },
    viewModel: HostDetailViewModel = hiltViewModel(),
) {
    // No "Exploits" tile here on purpose: the Exploit Finder needs a service
    // (ip + port + service name) to populate the search. Entry point is via
    // Port Scanner → tap the bug icon on a discovered port row.
    val actions = listOf(
        ActionItem(Icons.Default.Radar, "Port Scanner") { onPortScanner(viewModel.ip) },
        ActionItem(Icons.AutoMirrored.Filled.AltRoute, "Traceroute") { onTraceroute(viewModel.ip) },
        ActionItem(Icons.AutoMirrored.Filled.Send, "Packet Forger") { onPacketForger(viewModel.ip) },
        ActionItem(Icons.Default.Security, "Sniffer") { onMitmSniffer(viewModel.ip) },
        ActionItem(Icons.Default.Dns, "DNS Spoof") { onMitmDnsSpoof(viewModel.ip) },
        ActionItem(Icons.Default.Block, "Kill") { onMitmKill(viewModel.ip) },
        ActionItem(Icons.Default.NetworkCheck, "Packet Capture") { onPacketCapture(viewModel.ip) },
    )

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(viewModel.hostName ?: viewModel.ip)
                        Text(
                            buildString {
                                append(viewModel.ip)
                                viewModel.mac?.let { append(" • $it") }
                                viewModel.manufacturer?.let { append(" • $it") }
                            },
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                ),
            )
        },
    ) { padding ->
        LazyVerticalGrid(
            columns = GridCells.Fixed(2),
            modifier = Modifier.fillMaxSize().padding(padding).padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(actions) { action ->
                ActionCard(action)
            }
        }
    }
}

@Composable
private fun ActionCard(action: ActionItem) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .height(100.dp)
            .then(if (action.enabled) Modifier.clickable(onClick = action.onClick) else Modifier),
        colors = CardDefaults.cardColors(
            containerColor = if (action.enabled)
                MaterialTheme.colorScheme.secondaryContainer
            else
                MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
        ),
    ) {
        Column(
            modifier = Modifier.fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(
                action.icon,
                contentDescription = action.label,
                modifier = Modifier.size(32.dp),
                tint = if (action.enabled)
                    MaterialTheme.colorScheme.onSecondaryContainer
                else
                    MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
            )
            Spacer(Modifier.height(8.dp))
            Text(
                action.label,
                style = MaterialTheme.typography.labelLarge,
                color = if (action.enabled)
                    MaterialTheme.colorScheme.onSecondaryContainer
                else
                    MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
            )
        }
    }
}

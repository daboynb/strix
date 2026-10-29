package org.csploit.strix.ui.hostdetail

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.AltRoute
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

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
    val manufacturer by viewModel.manufacturer.collectAsStateWithLifecycle()
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
            HostDetailTopBar(
                ip = viewModel.ip,
                hostName = viewModel.hostName,
                mac = viewModel.mac,
                manufacturer = manufacturer,
                onBack = onBack,
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

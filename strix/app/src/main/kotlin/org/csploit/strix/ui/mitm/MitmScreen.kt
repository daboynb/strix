package org.csploit.strix.ui.mitm

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.csploit.strix.data.MitmMode

@Composable
fun MitmScreen(
    onBack: () -> Unit,
    viewModel: MitmViewModel = hiltViewModel(),
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val listState = rememberLazyListState()

    LaunchedEffect(uiState.logLines.size) {
        if (uiState.logLines.isNotEmpty()) {
            listState.animateScrollToItem(uiState.logLines.size - 1)
        }
    }

    Scaffold(
        topBar = {
            MitmTopBar(
                uiState = uiState,
                ip = viewModel.ip,
                onBack = onBack,
                onStart = { viewModel.start() },
                onStop = { viewModel.stop() },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            // Network info
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp),
                horizontalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text(
                    "Interface: ${uiState.iface}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            // DNS entries editor (only in DNS_SPOOF mode)
            if (uiState.mode == MitmMode.DNS_SPOOF) {
                DnsEntriesEditor(
                    entries = uiState.dnsEntries,
                    enabled = !uiState.isRunning,
                    onUpdate = { i, e -> viewModel.updateDnsEntry(i, e) },
                    onAdd = { viewModel.addDnsEntry() },
                    onRemove = { viewModel.removeDnsEntry(it) },
                )
            }

            // Kill status banner
            if (uiState.mode == MitmMode.KILL && uiState.isRunning) {
                KillStatusBanner(uiState.killActive)
            }

            // Error banner
            uiState.error?.let { error ->
                MitmErrorBanner(error)
            }

            // Captured credentials
            if (uiState.credentials.isNotEmpty()) {
                Text(
                    "Captured Credentials (${uiState.credentials.size})",
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp),
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.error,
                )
                for (cred in uiState.credentials) {
                    CredentialCard(cred)
                }
                Spacer(Modifier.height(4.dp))
            }

            // Live log
            MitmLogList(uiState.logLines, listState)
        }
    }
}

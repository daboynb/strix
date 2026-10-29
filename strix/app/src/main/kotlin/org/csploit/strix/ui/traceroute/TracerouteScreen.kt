package org.csploit.strix.ui.traceroute

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

@Composable
fun TracerouteScreen(
    onBack: () -> Unit,
    viewModel: TracerouteViewModel = hiltViewModel(),
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    Scaffold(
        topBar = {
            TracerouteTopBar(
                ip = viewModel.ip,
                isTracing = uiState.isTracing,
                onBack = onBack,
                onStart = { viewModel.startTrace() },
                onStop = { viewModel.stopTrace() },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            if (uiState.isTracing) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }

            uiState.error?.let {
                Text(
                    it,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            }

            // Header
            if (uiState.hops.isNotEmpty()) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                ) {
                    Text("HOP", modifier = Modifier.width(48.dp), style = MaterialTheme.typography.labelSmall)
                    Text("RTT", modifier = Modifier.width(80.dp), style = MaterialTheme.typography.labelSmall)
                    Text("ADDRESS", modifier = Modifier.weight(1f), style = MaterialTheme.typography.labelSmall)
                }
                HorizontalDivider()
            }

            LazyColumn(modifier = Modifier.fillMaxSize()) {
                items(uiState.hops, key = { it.hopNumber }) { hop ->
                    HopRow(hop)
                }
            }
        }
    }
}

package org.csploit.strix.ui.packetcapture

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

@Composable
fun PacketCaptureScreen(
    onBack: () -> Unit,
    viewModel: PacketCaptureViewModel = hiltViewModel(),
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
            PacketCaptureTopBar(
                uiState = uiState,
                onBack = onBack,
                onStart = { viewModel.start() },
                onStop = { viewModel.stop() },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            // Filter + verbose toggle
            Row(
                modifier = Modifier.fillMaxWidth().padding(12.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OutlinedTextField(
                    value = uiState.filter,
                    onValueChange = { viewModel.setFilter(it) },
                    enabled = !uiState.isRunning,
                    label = { Text("BPF Filter") },
                    placeholder = { Text("host 192.168.1.1 and port 80") },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                )
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text("Verbose", style = MaterialTheme.typography.labelSmall)
                    Switch(
                        checked = uiState.verbose,
                        onCheckedChange = { viewModel.setVerbose(it) },
                        enabled = !uiState.isRunning,
                    )
                }
            }

            // Live packet log
            PacketLogList(uiState.logLines, listState)
        }
    }
}

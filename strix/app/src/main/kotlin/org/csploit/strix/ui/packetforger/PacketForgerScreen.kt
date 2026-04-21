package org.csploit.strix.ui.packetforger

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PacketForgerScreen(
    onBack: () -> Unit,
    viewModel: PacketForgerViewModel = hiltViewModel(),
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("Packet Forger")
                        Text(viewModel.ip, style = MaterialTheme.typography.bodySmall)
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    if (uiState.isSending) {
                        CircularProgressIndicator(
                            modifier = Modifier.padding(12.dp),
                            strokeWidth = 2.dp,
                        )
                    } else {
                        IconButton(onClick = { viewModel.send() }) {
                            Icon(Icons.AutoMirrored.Filled.Send, contentDescription = "Send")
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
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // Protocol selector
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Protocol.entries.forEach { proto ->
                    FilterChip(
                        selected = uiState.protocol == proto,
                        onClick = { viewModel.setProtocol(proto) },
                        label = { Text(proto.name) },
                        enabled = !uiState.isSending,
                    )
                }
            }

            // Port
            OutlinedTextField(
                value = uiState.port,
                onValueChange = { viewModel.setPort(it) },
                label = { Text("Port") },
                singleLine = true,
                enabled = !uiState.isSending,
                modifier = Modifier.fillMaxWidth(),
            )

            // Payload
            OutlinedTextField(
                value = uiState.payload,
                onValueChange = { viewModel.setPayload(it) },
                label = { Text("Payload") },
                enabled = !uiState.isSending,
                minLines = 3,
                maxLines = 6,
                modifier = Modifier.fillMaxWidth(),
            )

            // Wait response checkbox
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(
                    checked = uiState.waitResponse,
                    onCheckedChange = { viewModel.setWaitResponse(it) },
                    enabled = !uiState.isSending,
                )
                Text("Wait for response (5s timeout)")
            }

            // WoL button
            if (viewModel.mac != null) {
                TextButton(
                    onClick = { viewModel.sendWol() },
                    enabled = !uiState.isSending,
                ) {
                    Icon(Icons.Default.PowerSettingsNew, contentDescription = null, modifier = Modifier.padding(end = 4.dp))
                    Text("Wake-on-LAN (${viewModel.mac})")
                }
            }

            // Error
            uiState.error?.let {
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            }

            // Response
            uiState.response?.let { resp ->
                Text("Response:", style = MaterialTheme.typography.labelMedium)
                Spacer(Modifier.height(4.dp))
                Text(
                    resp.ifEmpty { "(empty)" },
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(MaterialTheme.colorScheme.surfaceContainerLowest)
                        .padding(12.dp),
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                )
            }
        }
    }
}

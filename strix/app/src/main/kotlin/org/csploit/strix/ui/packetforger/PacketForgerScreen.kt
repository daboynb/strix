package org.csploit.strix.ui.packetforger

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

@Composable
fun PacketForgerScreen(
    onBack: () -> Unit,
    viewModel: PacketForgerViewModel = hiltViewModel(),
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    Scaffold(
        topBar = {
            PacketForgerTopBar(
                ip = viewModel.ip,
                isSending = uiState.isSending,
                onBack = onBack,
                onSend = { viewModel.send() },
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
            PacketForgerForm(
                uiState = uiState,
                onProtocol = { viewModel.setProtocol(it) },
                onPort = { viewModel.setPort(it) },
                onPayload = { viewModel.setPayload(it) },
                onWaitResponse = { viewModel.setWaitResponse(it) },
            )

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

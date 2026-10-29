package org.csploit.strix.ui.packetforger

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/** Protocol, port, payload and wait-for-response inputs. */
@Composable
internal fun PacketForgerForm(
    uiState: PacketForgerUiState,
    onProtocol: (Protocol) -> Unit,
    onPort: (String) -> Unit,
    onPayload: (String) -> Unit,
    onWaitResponse: (Boolean) -> Unit,
) {
    // Protocol selector
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Protocol.entries.forEach { proto ->
            FilterChip(
                selected = uiState.protocol == proto,
                onClick = { onProtocol(proto) },
                label = { Text(proto.name) },
                enabled = !uiState.isSending,
            )
        }
    }

    // Port
    OutlinedTextField(
        value = uiState.port,
        onValueChange = onPort,
        label = { Text("Port") },
        singleLine = true,
        enabled = !uiState.isSending,
        modifier = Modifier.fillMaxWidth(),
    )

    // Payload
    OutlinedTextField(
        value = uiState.payload,
        onValueChange = onPayload,
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
            onCheckedChange = onWaitResponse,
            enabled = !uiState.isSending,
        )
        Text("Wait for response (5s timeout)")
    }
}

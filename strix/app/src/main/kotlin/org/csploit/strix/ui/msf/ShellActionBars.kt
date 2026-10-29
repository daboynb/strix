package org.csploit.strix.ui.msf

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
internal fun ErrorBanner(message: String, onDismiss: (() -> Unit)?) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(TerminalError.copy(alpha = 0.18f))
            .padding(start = 12.dp, end = 4.dp, top = 4.dp, bottom = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            message,
            modifier = Modifier.weight(1f),
            color = TerminalText,
            fontSize = 12.sp,
        )
        if (onDismiss != null) {
            IconButton(onClick = onDismiss) {
                Icon(Icons.Default.Close, "Dismiss", tint = TerminalText)
            }
        }
    }
}

@Composable
internal fun MeterpreterQuickActions(
    onAction: (cmd: String, prefill: Boolean) -> Unit,
    onUpload: () -> Unit,
    onDownload: () -> Unit,
    onScreenshot: () -> Unit,
) {
    val scrollState = rememberScrollState()
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(scrollState)
            .padding(horizontal = 8.dp, vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Chip("sysinfo") { onAction("sysinfo", false) }
        Chip("getuid") { onAction("getuid", false) }
        Chip("ps") { onAction("ps", false) }
        Chip("hashdump") { onAction("hashdump", false) }
        Chip("getsystem") { onAction("getsystem", false) }
        Chip("migrate <pid>") { onAction("migrate", true) }
        Chip("screenshot", onScreenshot)
        Chip("upload", onUpload)
        Chip("download", onDownload)
        Chip("shell") { onAction("shell", false) }
        Chip("ifconfig") { onAction("ifconfig", false) }
    }
}

@Composable
private fun Chip(label: String, onClick: () -> Unit) {
    AssistChip(
        onClick = onClick,
        label = { Text(label, fontSize = 12.sp) },
        colors = AssistChipDefaults.assistChipColors(
            containerColor = Color(0xFF1A1A2E),
            labelColor = Color(0xFF4FC3F7),
        ),
    )
}

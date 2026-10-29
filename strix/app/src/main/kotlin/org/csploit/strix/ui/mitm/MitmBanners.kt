package org.csploit.strix.ui.mitm

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
internal fun KillStatusBanner(killActive: Boolean) {
    Text(
        if (killActive)
            "Connection killed — victim is offline until you Stop."
        else
            "Starting arpspoof + forwarding DROP/RST rules...",
        modifier = Modifier
            .fillMaxWidth()
            .background(
                if (killActive) MaterialTheme.colorScheme.errorContainer
                else MaterialTheme.colorScheme.surfaceContainerHigh,
            )
            .padding(12.dp),
        style = MaterialTheme.typography.bodyMedium,
        color = if (killActive)
            MaterialTheme.colorScheme.onErrorContainer
        else
            MaterialTheme.colorScheme.onSurface,
    )
}

@Composable
internal fun MitmErrorBanner(error: String) {
    Text(
        error,
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.errorContainer)
            .padding(12.dp),
        color = MaterialTheme.colorScheme.onErrorContainer,
        style = MaterialTheme.typography.bodyMedium,
    )
}

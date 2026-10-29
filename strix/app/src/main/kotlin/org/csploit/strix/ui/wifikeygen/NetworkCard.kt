package org.csploit.strix.ui.wifikeygen

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
internal fun NetworkCard(
    network: WifiNetwork,
    onGenerateKeys: () -> Unit,
) {
    // Keep container/content pairs matched: dynamic palettes (e.g. HyperOS) can
    // give light containers in dark mode, making mismatched text illegible.
    val colors = MaterialTheme.colorScheme
    val (containerColor, contentColor) = when {
        network.keys != null -> colors.errorContainer to colors.onErrorContainer
        network.hasKeygen -> colors.secondaryContainer to colors.onSecondaryContainer
        else -> colors.surfaceVariant to colors.onSurfaceVariant
    }
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp, vertical = 4.dp)
            .then(if (network.hasKeygen) Modifier.clickable(onClick = onGenerateKeys) else Modifier),
        colors = CardDefaults.cardColors(
            containerColor = containerColor,
            contentColor = contentColor,
        ),
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Icon(
                    if (network.encryption == "Open") Icons.Default.LockOpen else Icons.Default.Lock,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp),
                    tint = contentColor,
                )
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        network.ssid.ifEmpty { "<hidden>" },
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.Medium,
                    )
                    Text(
                        "${network.bssid} • ${network.encryption} • ${network.frequency}MHz",
                        style = MaterialTheme.typography.bodySmall,
                        color = contentColor,
                    )
                }
                if (network.hasKeygen) {
                    if (network.isGenerating) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(20.dp),
                            color = contentColor,
                            strokeWidth = 2.dp,
                        )
                    } else {
                        Icon(
                            Icons.Default.Key,
                            contentDescription = "Generate keys",
                            modifier = Modifier.size(20.dp),
                            tint = contentColor,
                        )
                    }
                }
                // Signal bars
                Text(
                    "▂▄▆█".take(network.level + 1),
                    fontSize = 10.sp,
                )
            }

            // Show generated keys
            network.keys?.forEach { key ->
                Text(
                    key,
                    modifier = Modifier.padding(start = 28.dp, top = 4.dp),
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodyMedium,
                    color = contentColor,
                )
            }

            network.error?.let {
                Text(
                    it,
                    modifier = Modifier.padding(start = 28.dp, top = 4.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = contentColor,
                )
            }
        }
    }
}

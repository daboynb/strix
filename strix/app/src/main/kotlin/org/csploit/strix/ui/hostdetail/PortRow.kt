package org.csploit.strix.ui.hostdetail

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import org.csploit.strix.domain.model.PortInfo

@Composable
fun PortRow(
    port: PortInfo,
    showBrute: Boolean = false,
    showExploit: Boolean = false,
    onBrute: () -> Unit = {},
    onExploit: () -> Unit = {},
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp, vertical = 2.dp),
        colors = CardDefaults.cardColors(
            containerColor = when (port.state) {
                "open" -> MaterialTheme.colorScheme.secondaryContainer
                "filtered" -> MaterialTheme.colorScheme.tertiaryContainer
                else -> MaterialTheme.colorScheme.surfaceVariant
            },
        ),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                "${port.number}/${port.protocol}",
                modifier = Modifier.width(80.dp),
                style = MaterialTheme.typography.bodyMedium,
                fontFamily = FontFamily.Monospace,
            )
            Text(
                port.state,
                modifier = Modifier.width(56.dp),
                style = MaterialTheme.typography.bodySmall,
                color = when (port.state) {
                    "open" -> MaterialTheme.colorScheme.primary
                    "filtered" -> MaterialTheme.colorScheme.tertiary
                    else -> MaterialTheme.colorScheme.onSurfaceVariant
                },
            )
            Column(modifier = Modifier.weight(1f)) {
                Text(port.service ?: "unknown", style = MaterialTheme.typography.bodyMedium)
                port.version?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            if (showExploit) {
                IconButton(onClick = onExploit, modifier = Modifier.size(32.dp)) {
                    Icon(Icons.Default.BugReport, contentDescription = "Find exploits", modifier = Modifier.size(18.dp))
                }
            }
            if (showBrute) {
                IconButton(onClick = onBrute, modifier = Modifier.size(32.dp)) {
                    Icon(Icons.Default.Lock, contentDescription = "Brute force", modifier = Modifier.size(18.dp))
                }
            }
        }
    }
}

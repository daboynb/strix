package org.csploit.strix.ui.hostlist

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Computer
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.PhoneAndroid
import androidx.compose.material.icons.filled.Router
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.csploit.strix.domain.model.Host

@Composable
internal fun HostCard(
    host: Host,
    isGateway: Boolean,
    isSelf: Boolean,
    onClick: () -> Unit = {},
) {
    val isManual = host.mac == "manual"
    val icon: ImageVector
    val label: String

    when {
        isGateway -> {
            icon = Icons.Default.Router
            label = "Gateway"
        }
        isSelf -> {
            icon = Icons.Default.PhoneAndroid
            label = "This device"
        }
        isManual -> {
            icon = Icons.Default.Language
            label = host.name ?: host.ip
        }
        else -> {
            icon = Icons.Default.Computer
            label = host.name ?: ""
        }
    }

    val alpha = if (host.connected) 1f else 0.5f
    // Content colors must pair with the container: dynamic palettes (HyperOS)
    // can give light containers in dark mode.
    val colors = MaterialTheme.colorScheme
    val (containerColor, contentColor) = when {
        isGateway -> colors.secondaryContainer to colors.onSecondaryContainer
        isSelf -> colors.tertiaryContainer to colors.onTertiaryContainer
        else -> colors.surfaceVariant to colors.onSurfaceVariant
    }

    Card(
        onClick = onClick,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp, vertical = 2.dp),
        colors = CardDefaults.cardColors(
            containerColor = containerColor,
            contentColor = contentColor,
        ),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = icon,
                contentDescription = label,
                modifier = Modifier.size(32.dp),
                tint = contentColor.copy(alpha = alpha),
            )
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = if (label.isNotEmpty()) label else host.ip,
                    style = MaterialTheme.typography.titleSmall,
                    color = contentColor.copy(alpha = alpha),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = host.ip,
                    style = MaterialTheme.typography.bodySmall,
                    color = contentColor.copy(alpha = alpha),
                )
                if (!isManual) {
                    Text(
                        text = host.mac,
                        style = MaterialTheme.typography.bodySmall,
                        color = contentColor.copy(alpha = alpha * 0.7f),
                    )
                }
            }
            if (!host.connected) {
                Icon(
                    imageVector = Icons.Default.Wifi,
                    contentDescription = "Disconnected",
                    modifier = Modifier.size(16.dp),
                    tint = contentColor.copy(alpha = 0.6f),
                )
            }
        }
    }
}

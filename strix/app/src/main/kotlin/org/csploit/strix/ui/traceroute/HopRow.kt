package org.csploit.strix.ui.traceroute

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.csploit.strix.domain.model.TracerouteHop

@Composable
internal fun HopRow(hop: TracerouteHop) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp),
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            "${hop.hopNumber}",
            modifier = Modifier.width(48.dp),
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodyMedium,
        )
        Text(
            hop.rttMs?.let { "%.1f ms".format(it) } ?: "*",
            modifier = Modifier.width(80.dp),
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodyMedium,
            color = if (hop.rttMs == null) MaterialTheme.colorScheme.outline else MaterialTheme.colorScheme.onSurface,
        )
        Column(modifier = Modifier.weight(1f)) {
            if (hop.hostname != null) {
                Text(
                    hop.hostname,
                    style = MaterialTheme.typography.bodyMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Text(
                hop.address ?: "* * *",
                style = if (hop.hostname != null) MaterialTheme.typography.bodySmall else MaterialTheme.typography.bodyMedium,
                color = if (hop.address == null) MaterialTheme.colorScheme.outline else MaterialTheme.colorScheme.onSurfaceVariant,
                fontFamily = FontFamily.Monospace,
            )
        }
    }
}

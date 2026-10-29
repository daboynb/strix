package org.csploit.strix.ui.packetcapture

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** Live tcpdump output, colored by protocol. */
@Composable
internal fun PacketLogList(logLines: List<String>, listState: LazyListState) {
    LazyColumn(
        state = listState,
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.surfaceContainerLowest)
            .padding(8.dp),
    ) {
        items(logLines) { line ->
            Text(
                line,
                fontFamily = FontFamily.Monospace,
                fontSize = 10.sp,
                color = when {
                    line.contains("ARP") -> MaterialTheme.colorScheme.tertiary
                    line.contains("ICMP") -> MaterialTheme.colorScheme.primary
                    line.contains("DNS") ||
                        line.contains(".53:") -> MaterialTheme.colorScheme.secondary
                    line.startsWith("[") -> MaterialTheme.colorScheme.tertiary
                    line.startsWith("tcpdump:") -> MaterialTheme.colorScheme.onSurfaceVariant
                    else -> MaterialTheme.colorScheme.onSurface
                },
            )
        }
    }
}

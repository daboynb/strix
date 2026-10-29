package org.csploit.strix.ui.mitm

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

@Composable
internal fun MitmLogList(logLines: List<String>, listState: LazyListState) {
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
                fontSize = 11.sp,
                color = when {
                    line.startsWith("[!]") -> MaterialTheme.colorScheme.error
                    line.startsWith("[+]") -> MaterialTheme.colorScheme.primary
                    line.startsWith("[tcp]") -> MaterialTheme.colorScheme.onSurfaceVariant
                    line.contains("poisoning") ||
                        line.contains("Unified sniffing") -> MaterialTheme.colorScheme.primary
                    line.startsWith("[") -> MaterialTheme.colorScheme.tertiary
                    else -> MaterialTheme.colorScheme.onSurface
                },
            )
        }
    }
}

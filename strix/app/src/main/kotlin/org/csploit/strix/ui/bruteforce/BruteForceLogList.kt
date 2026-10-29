package org.csploit.strix.ui.bruteforce

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.fillMaxWidth
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
internal fun ColumnScope.BruteForceLogList(logLines: List<String>, listState: LazyListState) {
    // Log output (takes remaining space, doesn't push other widgets out)
    LazyColumn(
        state = listState,
        modifier = Modifier
            .weight(1f)
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surfaceContainerLowest)
            .padding(8.dp),
    ) {
        items(logLines) { line ->
            Text(
                line,
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
                color = when {
                    line.contains("login:") -> MaterialTheme.colorScheme.error
                    line.startsWith("[") -> MaterialTheme.colorScheme.tertiary
                    else -> MaterialTheme.colorScheme.onSurface
                },
            )
        }
    }
}

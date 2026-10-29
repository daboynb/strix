package org.csploit.strix.ui.logs

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.csploit.strix.core.LogEntry
import org.csploit.strix.core.LogLevel

/**
 * One log entry, monospace. Content colors are always paired with the
 * container they sit on (dynamic palettes such as HyperOS can give light
 * containers in dark mode, so never mix e.g. `primary` text with a container).
 */
@Composable
fun LogEntryRow(entry: LogEntry) {
    val scheme = MaterialTheme.colorScheme
    val (container, content) = when (entry.level) {
        LogLevel.ERROR -> scheme.errorContainer to scheme.onErrorContainer
        LogLevel.WARN -> scheme.tertiaryContainer to scheme.onTertiaryContainer
        LogLevel.INFO -> Color.Transparent to scheme.onSurface
        LogLevel.DEBUG -> Color.Transparent to scheme.onSurfaceVariant
    }
    Text(
        text = entry.toText(),
        color = content,
        fontFamily = FontFamily.Monospace,
        fontSize = 11.sp,
        lineHeight = 14.sp,
        modifier = Modifier
            .fillMaxWidth()
            .background(container)
            .padding(horizontal = 8.dp, vertical = 1.dp),
    )
}

package org.csploit.strix.ui.msf

import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

internal val TerminalBar = Color(0xFF1A1A2E)
internal val TerminalBackground = Color(0xFF0D0D1A)
internal val TerminalText = Color(0xFFE0E0E0)
internal val TerminalMuted = Color(0xFF9E9EB0)
internal val TerminalAccent = Color(0xFF4FC3F7)
internal val TerminalError = Color(0xFFEF5350)

/** Session output, colored by line prefix; [modifier] carries the parent's weight. */
@Composable
internal fun ShellOutput(output: List<String>, listState: LazyListState, modifier: Modifier) {
    LazyColumn(
        state = listState,
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp, vertical = 4.dp),
    ) {
        items(output) { line ->
            val color = when {
                line.startsWith("$") -> Color(0xFF4FC3F7)
                line.startsWith("[read error") -> TerminalError
                line.startsWith("[session ") -> TerminalError
                line.startsWith("[") -> Color(0xFFFFB74D)
                else -> Color(0xFFE0E0E0)
            }
            Text(
                line,
                fontFamily = FontFamily.Monospace,
                fontSize = 12.sp,
                lineHeight = 16.sp,
                color = color,
            )
        }
    }
}

@Composable
internal fun ShellInputBar(
    input: String,
    sessionClosed: Boolean,
    onInputChange: (String) -> Unit,
    onSend: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(8.dp),
    ) {
        OutlinedTextField(
            value = input,
            onValueChange = onInputChange,
            modifier = Modifier.weight(1f),
            enabled = !sessionClosed,
            placeholder = {
                Text(if (sessionClosed) "session closed" else "command...")
            },
            singleLine = true,
            textStyle = MaterialTheme.typography.bodyMedium.copy(
                fontFamily = FontFamily.Monospace,
            ),
            // Sits on the fixed dark background: theme defaults
            // (onSurface/onSurfaceVariant) are unreadable in light theme.
            colors = OutlinedTextFieldDefaults.colors(
                focusedTextColor = TerminalText,
                unfocusedTextColor = TerminalText,
                disabledTextColor = TerminalMuted,
                focusedPlaceholderColor = TerminalMuted,
                unfocusedPlaceholderColor = TerminalMuted,
                disabledPlaceholderColor = TerminalMuted,
                cursorColor = TerminalAccent,
                focusedBorderColor = TerminalAccent,
                unfocusedBorderColor = TerminalMuted,
                disabledBorderColor = TerminalMuted.copy(alpha = 0.4f),
            ),
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
            keyboardActions = KeyboardActions(onSend = { onSend() }),
        )
        IconButton(
            onClick = onSend,
            enabled = !sessionClosed,
        ) {
            Icon(
                Icons.AutoMirrored.Filled.Send,
                "Send",
                tint = if (sessionClosed) TerminalMuted else TerminalAccent,
            )
        }
    }
}

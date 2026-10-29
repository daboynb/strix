package org.csploit.strix.ui.bruteforce

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.unit.dp
import kotlin.math.roundToInt

/** Charset chips + min/max length sliders for [PasswordMode.CHARSET]. */
@Composable
internal fun CharsetOptions(
    state: BruteForceUiState,
    enabled: Boolean,
    onCharsetChange: (lower: Boolean, upper: Boolean, digits: Boolean) -> Unit,
    onRangeChange: (min: Int, max: Int) -> Unit,
) {
    Row(
        horizontalArrangement = Arrangement.spacedBy(4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        FilterChip(
            selected = state.charsetLower,
            onClick = {
                onCharsetChange(!state.charsetLower, state.charsetUpper, state.charsetDigits)
            },
            label = { Text("a-z") },
            enabled = enabled,
        )
        FilterChip(
            selected = state.charsetUpper,
            onClick = {
                onCharsetChange(state.charsetLower, !state.charsetUpper, state.charsetDigits)
            },
            label = { Text("A-Z") },
            enabled = enabled,
        )
        FilterChip(
            selected = state.charsetDigits,
            onClick = {
                onCharsetChange(state.charsetLower, state.charsetUpper, !state.charsetDigits)
            },
            label = { Text("0-9") },
            enabled = enabled,
        )
    }
    Column {
        Text("Min length: ${state.passMin}", style = MaterialTheme.typography.labelSmall)
        Slider(
            value = state.passMin.toFloat(),
            onValueChange = { onRangeChange(it.roundToInt(), state.passMax) },
            valueRange = 1f..8f,
            steps = 6,
            enabled = enabled,
        )
        Text("Max length: ${state.passMax}", style = MaterialTheme.typography.labelSmall)
        Slider(
            value = state.passMax.toFloat(),
            onValueChange = { onRangeChange(state.passMin, it.roundToInt()) },
            valueRange = 1f..8f,
            steps = 6,
            enabled = enabled,
        )
    }
}

package org.csploit.strix.ui.bruteforce

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** Progress bar, hydra status line and the found-credentials banner. */
@Composable
internal fun BruteForceStatus(uiState: BruteForceUiState) {
    // Progress bar
    uiState.progress?.let { p ->
        LinearProgressIndicator(
            progress = { p },
            modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp),
        )
    }
    uiState.statusLine?.let { line ->
        Text(
            line,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 2.dp),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.primary,
            fontFamily = FontFamily.Monospace,
            fontSize = 10.sp,
        )
    }

    // Found credentials banner
    uiState.foundCreds?.let { creds ->
        Text(
            "FOUND: $creds",
            modifier = Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.errorContainer)
                .padding(12.dp),
            color = MaterialTheme.colorScheme.onErrorContainer,
            style = MaterialTheme.typography.titleSmall,
        )
    }
}

package org.csploit.strix.ui.bruteforce

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun WordlistsSection(
    state: BruteForceUiState,
    enabled: Boolean,
    onPickUsers: (android.net.Uri) -> Unit,
    onPickPasswords: (android.net.Uri) -> Unit,
    onClearUsers: () -> Unit,
    onClearPasswords: () -> Unit,
    onModeChange: (PasswordMode) -> Unit,
    onCharsetChange: (lower: Boolean, upper: Boolean, digits: Boolean) -> Unit,
    onRangeChange: (min: Int, max: Int) -> Unit,
) {
    val usersLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri -> uri?.let(onPickUsers) }
    val passwordsLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri -> uri?.let(onPickPasswords) }

    Column(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        // Users wordlist
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedButton(
                onClick = { usersLauncher.launch(arrayOf("*/*")) },
                enabled = enabled,
                modifier = Modifier.weight(1f),
            ) {
                Icon(Icons.Default.FileOpen, null, modifier = Modifier.width(16.dp))
                Spacer(Modifier.width(4.dp))
                Text(
                    state.customUsersPath?.substringAfterLast('/') ?: "Users: default",
                    maxLines = 1,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (state.customUsersPath != null) {
                IconButton(onClick = onClearUsers, enabled = enabled) {
                    Icon(Icons.Default.Clear, "Reset users wordlist")
                }
            }
        }

        // Password source toggle
        SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
            SegmentedButton(
                selected = state.passwordMode == PasswordMode.WORDLIST,
                onClick = { onModeChange(PasswordMode.WORDLIST) },
                enabled = enabled,
                shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2),
            ) { Text("Wordlist") }
            SegmentedButton(
                selected = state.passwordMode == PasswordMode.CHARSET,
                onClick = { onModeChange(PasswordMode.CHARSET) },
                enabled = enabled,
                shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2),
            ) { Text("Charset") }
        }

        if (state.passwordMode == PasswordMode.WORDLIST) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedButton(
                    onClick = { passwordsLauncher.launch(arrayOf("*/*")) },
                    enabled = enabled,
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(Icons.Default.FileOpen, null, modifier = Modifier.width(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text(
                        state.customPasswordsPath?.substringAfterLast('/') ?: "Passwords: default",
                        maxLines = 1,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                if (state.customPasswordsPath != null) {
                    IconButton(onClick = onClearPasswords, enabled = enabled) {
                        Icon(Icons.Default.Clear, "Reset passwords wordlist")
                    }
                }
            }
        } else {
            // Charset + length
            CharsetOptions(state, enabled, onCharsetChange, onRangeChange)
        }
    }
}

package org.csploit.strix.ui.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.csploit.strix.data.bundle.BundleOp
import org.csploit.strix.data.bundle.BundleState
import org.csploit.strix.data.bundle.BundleVersions

internal fun displayVersion(v: String?) = when (v) {
    null -> "Not installed"
    BundleVersions.LEGACY -> "Bundled with an older app"
    else -> v
}

/** Metasploit update-available card and last error/message (installed from the Metasploit screen). */
@Composable
internal fun MsfBundleNotice(msf: BundleState, onDismissMessages: () -> Unit) {
    if (msf.availableVersion != null) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.primaryContainer,
                contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
            ),
        ) {
            Text(
                "Metasploit ${msf.availableVersion} is available. Install it from the Metasploit screen.",
                modifier = Modifier.padding(12.dp),
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }

    val error = (msf.op as? BundleOp.Error)?.message
    (error ?: msf.message)?.let { text ->
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                "Metasploit: $text",
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.bodySmall,
                color = if (error != null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
            )
            TextButton(onClick = onDismissMessages) { Text("OK") }
        }
    }
}

@Composable
internal fun VersionRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium)
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.padding(start = 16.dp),
        )
    }
}

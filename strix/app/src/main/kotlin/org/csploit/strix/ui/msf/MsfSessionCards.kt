package org.csploit.strix.ui.msf

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
internal fun MsfActionsCard(onExploitFinder: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("Actions", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = onExploitFinder,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(Icons.Default.Terminal, null, Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text("Exploit Finder")
            }
        }
    }
}

@Composable
internal fun SessionsHeader(count: Int, onRefresh: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            "Sessions ($count)",
            style = MaterialTheme.typography.titleMedium,
        )
        IconButton(onClick = onRefresh) {
            Icon(Icons.Default.Refresh, "Refresh")
        }
    }
}

@Composable
internal fun SessionCard(
    session: org.csploit.strix.domain.model.MsfSession,
    onShell: () -> Unit,
    onStop: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    "#${session.id} ${session.type}",
                    style = MaterialTheme.typography.titleSmall,
                )
                Text(
                    "${session.targetHost}:${session.targetPort}",
                    style = MaterialTheme.typography.bodySmall,
                )
                if (session.viaExploit.isNotEmpty()) {
                    Text(
                        session.viaExploit.substringAfterLast('/'),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            if (session.type == "shell" || session.type == "meterpreter") {
                IconButton(onClick = onShell) {
                    Icon(Icons.Default.Terminal, "Shell")
                }
            }
            IconButton(onClick = onStop) {
                Icon(Icons.Default.Delete, "Stop", tint = MaterialTheme.colorScheme.error)
            }
        }
    }
}

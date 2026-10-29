package org.csploit.strix.ui.mitm

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.csploit.strix.data.DnsEntry

@Composable
internal fun DnsEntriesEditor(
    entries: List<DnsEntry>,
    enabled: Boolean,
    onUpdate: (Int, DnsEntry) -> Unit,
    onAdd: () -> Unit,
    onRemove: (Int) -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp),
    ) {
        Text(
            "DNS Entries",
            style = MaterialTheme.typography.labelLarge,
            modifier = Modifier.padding(bottom = 4.dp),
        )

        entries.forEachIndexed { index, entry ->
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OutlinedTextField(
                    value = entry.hostname,
                    onValueChange = { onUpdate(index, entry.copy(hostname = it)) },
                    enabled = enabled,
                    label = { Text("Hostname") },
                    placeholder = { Text("*.example.com") },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodySmall,
                )
                Spacer(Modifier.width(4.dp))
                OutlinedTextField(
                    value = entry.address,
                    onValueChange = { onUpdate(index, entry.copy(address = it)) },
                    enabled = enabled,
                    label = { Text("IP") },
                    placeholder = { Text("192.168.1.100") },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodySmall,
                )
                if (entries.size > 1) {
                    IconButton(
                        onClick = { onRemove(index) },
                        enabled = enabled,
                        modifier = Modifier.size(36.dp),
                    ) {
                        Icon(
                            Icons.Default.Close,
                            contentDescription = "Remove",
                            modifier = Modifier.size(18.dp),
                        )
                    }
                }
            }
        }

        TextButton(
            onClick = onAdd,
            enabled = enabled,
        ) {
            Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(4.dp))
            Text("Add entry")
        }
    }
}

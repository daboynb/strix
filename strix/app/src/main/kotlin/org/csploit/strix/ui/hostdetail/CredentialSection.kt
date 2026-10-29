package org.csploit.strix.ui.hostdetail

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.csploit.strix.domain.model.DefaultCreds

@Composable
fun CredentialSection(
    isTesting: Boolean,
    credsTested: Boolean,
    credsResult: DefaultCreds?,
    hydraStatus: String?,
    onTest: () -> Unit,
    onStop: () -> Unit,
) {
    // Keep container/content pairs matched (dynamic palettes can invert them).
    val colors = MaterialTheme.colorScheme
    val (containerColor, contentColor) = when {
        credsResult != null -> colors.errorContainer to colors.onErrorContainer
        credsTested -> colors.secondaryContainer to colors.onSecondaryContainer
        else -> colors.surfaceVariant to colors.onSurfaceVariant
    }
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp, vertical = 4.dp),
        colors = CardDefaults.cardColors(
            containerColor = containerColor,
            contentColor = contentColor,
        ),
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            when {
                isTesting -> {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        CircularProgressIndicator(modifier = Modifier.padding(4.dp), color = contentColor)
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Testing credentials (hydra)...")
                            hydraStatus?.let {
                                Text(it, style = MaterialTheme.typography.bodySmall, color = contentColor)
                            }
                        }
                        IconButton(onClick = onStop) {
                            Icon(Icons.Default.Stop, contentDescription = "Stop")
                        }
                    }
                }
                credsResult != null -> {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Icon(Icons.Default.LockOpen, contentDescription = null, tint = contentColor)
                        Column {
                            Text("Default credentials found!", style = MaterialTheme.typography.titleSmall, color = contentColor)
                            Text("${credsResult.username}:${credsResult.password} (${credsResult.service})", style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
                credsTested -> {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Icon(Icons.Default.Lock, contentDescription = null, tint = contentColor)
                        Text("No default credentials found")
                    }
                }
                else -> {
                    Button(onClick = onTest, modifier = Modifier.fillMaxWidth()) {
                        Icon(Icons.Default.Lock, contentDescription = null)
                        Spacer(Modifier.width(8.dp))
                        Text("Test default credentials")
                    }
                }
            }
        }
    }
}

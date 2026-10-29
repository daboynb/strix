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
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.CloudOff
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.csploit.strix.data.DaemonState

@Composable
internal fun DaemonStatusCard(
    daemonState: DaemonState,
    msfInstalled: Boolean,
    isConnected: Boolean,
    connecting: Boolean,
    msfVersion: String?,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onConnect: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    if (isConnected) Icons.Default.Cloud else Icons.Default.CloudOff,
                    null,
                    tint = when {
                        isConnected -> MaterialTheme.colorScheme.primary
                        daemonState == DaemonState.READY -> MaterialTheme.colorScheme.tertiary
                        else -> MaterialTheme.colorScheme.onSurfaceVariant
                    },
                )
                Spacer(Modifier.width(12.dp))
                Column {
                    Text(
                        when {
                            isConnected -> "Connected"
                            daemonState == DaemonState.READY -> "Daemon ready, not connected"
                            daemonState == DaemonState.STARTING -> "Starting daemon..."
                            daemonState == DaemonState.FAILED -> "Daemon failed"
                            !msfInstalled -> "MSF not installed"
                            else -> "Daemon stopped"
                        },
                        style = MaterialTheme.typography.titleSmall,
                    )
                    msfVersion?.let {
                        Text(
                            "MSF $it",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }

            Spacer(Modifier.height(12.dp))

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                when {
                    daemonState == DaemonState.STARTING || connecting -> {
                        CircularProgressIndicator(modifier = Modifier.size(36.dp))
                    }
                    daemonState == DaemonState.STOPPED || daemonState == DaemonState.FAILED -> {
                        Button(
                            onClick = onStart,
                            enabled = msfInstalled,
                        ) {
                            Icon(Icons.Default.PlayArrow, null, Modifier.size(18.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("Start Daemon")
                        }
                        OutlinedButton(onClick = onConnect) {
                            Text("Connect Remote")
                        }
                    }
                    daemonState == DaemonState.READY && !isConnected -> {
                        Button(onClick = onConnect) {
                            Text("Connect")
                        }
                        OutlinedButton(
                            onClick = onStop,
                            colors = ButtonDefaults.outlinedButtonColors(
                                contentColor = MaterialTheme.colorScheme.error,
                            ),
                        ) {
                            Icon(Icons.Default.Stop, null, Modifier.size(18.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("Stop")
                        }
                    }
                    isConnected -> {
                        OutlinedButton(
                            onClick = onStop,
                            colors = ButtonDefaults.outlinedButtonColors(
                                contentColor = MaterialTheme.colorScheme.error,
                            ),
                        ) {
                            Icon(Icons.Default.Stop, null, Modifier.size(18.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("Disconnect & Stop")
                        }
                    }
                }
            }
        }
    }
}

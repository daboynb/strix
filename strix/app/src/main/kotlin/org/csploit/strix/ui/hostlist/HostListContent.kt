package org.csploit.strix.ui.hostlist

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.csploit.strix.domain.model.Host
import org.csploit.strix.domain.model.NetworkInfo

/** Discovered hosts, or an empty-state message when idle with none found. */
@Composable
internal fun HostListContent(
    hosts: List<Host>,
    networkInfo: NetworkInfo?,
    isScanning: Boolean,
    onHostClick: (Host, Boolean) -> Unit,
) {
    if (hosts.isEmpty() && !isScanning) {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center,
        ) {
            Text("No hosts discovered", style = MaterialTheme.typography.bodyLarge)
        }
    } else {
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            items(hosts, key = { it.ip }) { host ->
                val isGateway = host.ip == networkInfo?.gatewayIp
                val isSelf = host.ip == networkInfo?.localIp
                HostCard(
                    host = host,
                    isGateway = isGateway,
                    isSelf = isSelf,
                    onClick = { onHostClick(host, isGateway) },
                )
            }
        }
    }
}

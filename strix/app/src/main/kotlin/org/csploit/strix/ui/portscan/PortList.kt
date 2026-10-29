package org.csploit.strix.ui.portscan

import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.csploit.strix.data.HydraModules
import org.csploit.strix.domain.model.PortInfo
import org.csploit.strix.ui.hostdetail.PortRow

/** Column header + scanned ports, each with brute-force/exploit actions. */
@Composable
internal fun PortList(
    ports: List<PortInfo>,
    onBrute: (PortInfo) -> Unit,
    onExploit: (PortInfo) -> Unit,
) {
    if (ports.isNotEmpty()) {
        Row(modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)) {
            Text("PORT", modifier = Modifier.width(80.dp), style = MaterialTheme.typography.labelSmall)
            Text("STATE", modifier = Modifier.width(64.dp), style = MaterialTheme.typography.labelSmall)
            Text("SERVICE", modifier = Modifier.weight(1f), style = MaterialTheme.typography.labelSmall)
        }
        HorizontalDivider()
    }

    LazyColumn(modifier = Modifier.fillMaxSize()) {
        items(ports, key = { "${it.number}/${it.protocol}" }) { port ->
            val attacks = HydraModules.forService(port.service, port.number)
            PortRow(
                port = port,
                showBrute = port.state == "open" && attacks.isNotEmpty(),
                showExploit = port.state == "open",
                onBrute = { onBrute(port) },
                onExploit = { onExploit(port) },
            )
        }
    }
}

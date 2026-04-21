package org.csploit.strix.ui.portscan

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.csploit.strix.data.HydraModules
import org.csploit.strix.ui.hostdetail.PortRow

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PortScannerScreen(
    onBack: () -> Unit,
    onBruteForce: (String, Int, String?) -> Unit = { _, _, _ -> },
    onExploitFinder: (String, Int, String?) -> Unit = { _, _, _ -> },
    viewModel: PortScannerViewModel = hiltViewModel(),
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("Port Scanner")
                        Text(viewModel.ip, style = MaterialTheme.typography.bodySmall)
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    if (uiState.isScanning) {
                        IconButton(onClick = { viewModel.stopScan() }) {
                            Icon(Icons.Default.Stop, contentDescription = "Stop")
                        }
                    } else {
                        IconButton(onClick = { viewModel.startScan() }) {
                            Icon(Icons.Default.PlayArrow, contentDescription = "Scan")
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                ),
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            // Port range input
            var portRangeText by remember { mutableStateOf(viewModel.portRange) }
            OutlinedTextField(
                value = portRangeText,
                onValueChange = { portRangeText = it; viewModel.setPortRange(it) },
                label = { Text("Port range") },
                placeholder = { Text("top 1000 (default)") },
                enabled = !uiState.isScanning,
                singleLine = true,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
            )

            if (uiState.isScanning) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                uiState.progress?.let {
                    Text(
                        "Scanning... $it",
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }

            // Scan info
            Column(
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                uiState.os?.let { InfoLine("OS", it) }
                uiState.fingerprint?.serverHeader?.let { InfoLine("HTTP Server", it) }
                uiState.fingerprint?.title?.let { InfoLine("Page Title", it) }
                uiState.error?.let {
                    Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
            }

            // Port list header
            if (uiState.ports.isNotEmpty()) {
                Row(modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)) {
                    Text("PORT", modifier = Modifier.width(80.dp), style = MaterialTheme.typography.labelSmall)
                    Text("STATE", modifier = Modifier.width(64.dp), style = MaterialTheme.typography.labelSmall)
                    Text("SERVICE", modifier = Modifier.weight(1f), style = MaterialTheme.typography.labelSmall)
                }
                HorizontalDivider()
            }

            LazyColumn(modifier = Modifier.fillMaxSize()) {
                items(uiState.ports, key = { "${it.number}/${it.protocol}" }) { port ->
                    val attacks = HydraModules.forService(port.service, port.number)
                    PortRow(
                        port = port,
                        showBrute = port.state == "open" && attacks.isNotEmpty(),
                        showExploit = port.state == "open",
                        onBrute = { onBruteForce(viewModel.ip, port.number, port.service) },
                        onExploit = {
                            // Build search query from version + service
                            // "vsftpd 2.3.4" → "vsftpd" (specific product name)
                            // "Linux telnetd" → "telnetd" (skip generic OS names)
                            // "Apache httpd 2.2.8" → "Apache" (product name)
                            // fallback to service name like "ftp"
                            val genericTerms = setOf("linux", "unix", "gnu", "microsoft", "windows")
                            val versionTokens = port.version?.split(" ")?.filter {
                                it.lowercase() !in genericTerms && !it.matches(Regex("^[\\d.]+$"))
                            }
                            val searchTerm = versionTokens?.firstOrNull()
                                ?: port.service
                            onExploitFinder(viewModel.ip, port.number, searchTerm)
                        },
                    )
                }
            }
        }
    }
}

@Composable
private fun InfoLine(label: String, value: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text("$label: ", style = MaterialTheme.typography.labelSmall)
        Text(value, style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

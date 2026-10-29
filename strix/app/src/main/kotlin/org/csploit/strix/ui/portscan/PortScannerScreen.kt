package org.csploit.strix.ui.portscan

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

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
            PortScannerTopBar(
                ip = viewModel.ip,
                isScanning = uiState.isScanning,
                onBack = onBack,
                onStart = { viewModel.startScan() },
                onStop = { viewModel.stopScan() },
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
            ScanInfoSection(uiState)

            PortList(
                ports = uiState.ports,
                onBrute = { port -> onBruteForce(viewModel.ip, port.number, port.service) },
                onExploit = { port -> onExploitFinder(viewModel.ip, port.number, exploitSearchTerm(port)) },
            )
        }
    }
}

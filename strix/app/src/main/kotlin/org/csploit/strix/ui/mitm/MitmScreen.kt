package org.csploit.strix.ui.mitm

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.csploit.strix.data.DnsEntry
import org.csploit.strix.data.MitmMode

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MitmScreen(
    onBack: () -> Unit,
    viewModel: MitmViewModel = hiltViewModel(),
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val listState = rememberLazyListState()

    LaunchedEffect(uiState.logLines.size) {
        if (uiState.logLines.isNotEmpty()) {
            listState.animateScrollToItem(uiState.logLines.size - 1)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(
                            when (uiState.mode) {
                                MitmMode.SNIFFER -> "Sniffer"
                                MitmMode.DNS_SPOOF -> "DNS Spoof"
                                MitmMode.KILL -> "Connection Killer"
                            },
                        )
                        Text(
                            "${viewModel.ip} via ${uiState.gateway}",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    if (uiState.isRunning) {
                        IconButton(onClick = { viewModel.stop() }) {
                            Icon(Icons.Default.Stop, contentDescription = "Stop")
                        }
                    } else {
                        IconButton(onClick = { viewModel.start() }) {
                            Icon(Icons.Default.PlayArrow, contentDescription = "Start")
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
            // Network info
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp),
                horizontalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text(
                    "Interface: ${uiState.iface}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            // DNS entries editor (only in DNS_SPOOF mode)
            if (uiState.mode == MitmMode.DNS_SPOOF) {
                DnsEntriesEditor(
                    entries = uiState.dnsEntries,
                    enabled = !uiState.isRunning,
                    onUpdate = { i, e -> viewModel.updateDnsEntry(i, e) },
                    onAdd = { viewModel.addDnsEntry() },
                    onRemove = { viewModel.removeDnsEntry(it) },
                )
            }

            // Kill status banner
            if (uiState.mode == MitmMode.KILL && uiState.isRunning) {
                Text(
                    if (uiState.killActive)
                        "Connection killed — victim is offline until you Stop."
                    else
                        "Starting arpspoof + forwarding DROP/RST rules...",
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            if (uiState.killActive) MaterialTheme.colorScheme.errorContainer
                            else MaterialTheme.colorScheme.surfaceContainerHigh,
                        )
                        .padding(12.dp),
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (uiState.killActive)
                        MaterialTheme.colorScheme.onErrorContainer
                    else
                        MaterialTheme.colorScheme.onSurface,
                )
            }

            // Error banner
            uiState.error?.let { error ->
                Text(
                    error,
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(MaterialTheme.colorScheme.errorContainer)
                        .padding(12.dp),
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }

            // Captured credentials
            if (uiState.credentials.isNotEmpty()) {
                Text(
                    "Captured Credentials (${uiState.credentials.size})",
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp),
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.error,
                )
                for (cred in uiState.credentials) {
                    CredentialCard(cred)
                }
                Spacer(Modifier.height(4.dp))
            }

            // Live log
            LazyColumn(
                state = listState,
                modifier = Modifier
                    .fillMaxSize()
                    .background(MaterialTheme.colorScheme.surfaceContainerLowest)
                    .padding(8.dp),
            ) {
                items(uiState.logLines) { line ->
                    Text(
                        line,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        color = when {
                            line.startsWith("[!]") -> MaterialTheme.colorScheme.error
                            line.startsWith("[+]") -> MaterialTheme.colorScheme.primary
                            line.startsWith("[tcp]") -> MaterialTheme.colorScheme.onSurfaceVariant
                            line.contains("poisoning") ||
                                line.contains("Unified sniffing") -> MaterialTheme.colorScheme.primary
                            line.startsWith("[") -> MaterialTheme.colorScheme.tertiary
                            else -> MaterialTheme.colorScheme.onSurface
                        },
                    )
                }
            }
        }
    }
}

@Composable
private fun CredentialCard(cred: CapturedCredential) {
    val clipboardManager = LocalClipboardManager.current
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 3.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer,
        ),
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            // Protocol badge + endpoint
            Row(
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    cred.protocol,
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.error,
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    cred.endpoint,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                    modifier = Modifier.weight(1f),
                )
                IconButton(
                    onClick = {
                        clipboardManager.setText(
                            AnnotatedString("${cred.user}:${cred.pass}"),
                        )
                    },
                    modifier = Modifier.size(28.dp),
                ) {
                    Icon(
                        Icons.Default.ContentCopy,
                        contentDescription = "Copy",
                        modifier = Modifier.size(16.dp),
                        tint = MaterialTheme.colorScheme.onErrorContainer,
                    )
                }
            }
            Spacer(Modifier.height(4.dp))
            // User
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Default.Person,
                    contentDescription = null,
                    modifier = Modifier.size(14.dp),
                    tint = MaterialTheme.colorScheme.onErrorContainer,
                )
                Spacer(Modifier.width(6.dp))
                Text(
                    cred.user,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                )
            }
            // Password
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Default.Key,
                    contentDescription = null,
                    modifier = Modifier.size(14.dp),
                    tint = MaterialTheme.colorScheme.onErrorContainer,
                )
                Spacer(Modifier.width(6.dp))
                Text(
                    cred.pass,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }
    }
}


@Composable
private fun DnsEntriesEditor(
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

package org.csploit.strix.ui.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlin.math.roundToInt

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onBack: () -> Unit,
    viewModel: SettingsViewModel = hiltViewModel(),
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                ),
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            // Nmap section
            SectionHeader("Nmap")

            SliderSetting(
                label = "Timing template",
                value = uiState.nmapTiming,
                valueLabel = "T${uiState.nmapTiming}" + when (uiState.nmapTiming) {
                    1 -> " (sneaky)"
                    2 -> " (polite)"
                    3 -> " (normal)"
                    4 -> " (aggressive)"
                    5 -> " (insane)"
                    else -> ""
                },
                range = 1f..5f,
                steps = 3,
                onValueChange = { viewModel.setNmapTiming(it) },
            )

            OutlinedTextField(
                value = uiState.defaultPortRange,
                onValueChange = { viewModel.setDefaultPortRange(it) },
                label = { Text("Default port range") },
                placeholder = { Text("top 1000 (leave empty)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

            OutlinedTextField(
                value = uiState.dnsServer,
                onValueChange = { viewModel.setDnsServer(it) },
                label = { Text("DNS server") },
                placeholder = { Text("system default (leave empty)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

            OutlinedTextField(
                value = uiState.customNmapArgs,
                onValueChange = { viewModel.setCustomNmapArgs(it) },
                label = { Text("Custom nmap args") },
                placeholder = { Text("--script vuln  -A  --script-args ...") },
                singleLine = true,
                supportingText = { Text("Appended after -sS -sV -O; overrides nothing") },
                modifier = Modifier.fillMaxWidth(),
            )

            HorizontalDivider()

            // Hydra section
            SectionHeader("Hydra")

            SliderSetting(
                label = "Parallel threads",
                value = uiState.hydraThreads,
                valueLabel = "${uiState.hydraThreads}",
                range = 1f..16f,
                steps = 14,
                onValueChange = { viewModel.setHydraThreads(it) },
            )

            HorizontalDivider()

            // Network section
            SectionHeader("Network")

            SliderSetting(
                label = "Socket timeout",
                value = uiState.socketTimeoutSec,
                valueLabel = "${uiState.socketTimeoutSec}s",
                range = 1f..30f,
                steps = 28,
                onValueChange = { viewModel.setSocketTimeout(it) },
            )
        }
    }
}

@Composable
private fun SectionHeader(title: String) {
    Text(
        title,
        style = MaterialTheme.typography.titleMedium,
        color = MaterialTheme.colorScheme.primary,
    )
}

@Composable
private fun SliderSetting(
    label: String,
    value: Int,
    valueLabel: String,
    range: ClosedFloatingPointRange<Float>,
    steps: Int,
    onValueChange: (Int) -> Unit,
) {
    Column {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(label, style = MaterialTheme.typography.bodyMedium)
            Text(valueLabel, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.primary)
        }
        Slider(
            value = value.toFloat(),
            onValueChange = { onValueChange(it.roundToInt()) },
            valueRange = range,
            steps = steps,
        )
    }
}

package org.csploit.strix.ui.settings

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier

/** Nmap, Hydra and Network settings, emitted directly into the parent settings Column. */
@Composable
internal fun ScanSettingsSections(uiState: SettingsUiState, viewModel: SettingsViewModel) {
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
        placeholder = { Text("Wi-Fi DNS (leave empty)") },
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

package org.csploit.strix.ui.settings

import android.text.format.DateUtils
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.csploit.strix.data.bundle.BundleOp
import org.csploit.strix.data.bundle.BundleVersions
import org.csploit.strix.data.bundle.BundleState
import org.csploit.strix.ui.bundles.BundleUpdateCard

private fun displayVersion(v: String?) = when (v) {
    null -> "Not installed"
    BundleVersions.LEGACY -> "Bundled with an older app"
    else -> v
}

@Composable
fun BundlesSection(
    uiState: SettingsUiState,
    tools: BundleState,
    msf: BundleState,
    checking: Boolean,
    onCheck: () -> Unit,
    onWifiOnly: (Boolean) -> Unit,
    onReinstallTools: () -> Unit,
    onDownloadTools: () -> Unit,
    onCancelTools: () -> Unit,
    onApplyTools: () -> Unit,
    onDismissTools: () -> Unit,
    onDismissMessages: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        VersionRow("Tools", displayVersion(tools.installedVersion) + (tools.source?.let { " ($it)" } ?: ""))
        VersionRow("Metasploit", displayVersion(msf.installedVersion))

        // Tools are updated from here (progress, pending swap, errors).
        BundleUpdateCard(
            state = tools,
            onDownload = onDownloadTools,
            onCancel = onCancelTools,
            onApply = onApplyTools,
            onDismiss = onDismissTools,
        )

        if (msf.availableVersion != null) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                ),
            ) {
                Text(
                    "Metasploit ${msf.availableVersion} is available. Install it from the Metasploit screen.",
                    modifier = Modifier.padding(12.dp),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }

        val error = (msf.op as? BundleOp.Error)?.message
        (error ?: msf.message)?.let { text ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "Metasploit: $text",
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.bodySmall,
                    color = if (error != null) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                )
                TextButton(onClick = onDismissMessages) { Text("OK") }
            }
        }

        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedButton(onClick = onCheck, enabled = !checking) { Text("Check for updates") }
            if (checking) CircularProgressIndicator(Modifier.size(20.dp))
        }
        Text(
            if (tools.lastCheckMs > 0) {
                "Last checked " + DateUtils.getRelativeTimeSpanString(tools.lastCheckMs)
            } else {
                "Never checked (automatic check runs at most once a day)"
            },
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text("Wi-Fi only downloads", style = MaterialTheme.typography.bodyMedium)
                Text(
                    "Also limits the automatic daily check",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Switch(checked = uiState.bundleWifiOnly, onCheckedChange = onWifiOnly)
        }

        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedButton(onClick = onReinstallTools, enabled = !uiState.reinstallingTools && !tools.op.busy) {
                Text("Reinstall tools from APK")
            }
            if (uiState.reinstallingTools) CircularProgressIndicator(Modifier.size(20.dp))
        }
        uiState.toolsMessage?.let {
            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun VersionRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium)
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.padding(start = 16.dp),
        )
    }
}

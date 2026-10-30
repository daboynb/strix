package org.csploit.strix.ui.bundles

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import org.csploit.strix.data.bundle.BundleOp
import org.csploit.strix.data.bundle.BundleVersions
import org.csploit.strix.data.bundle.BundleState

private fun mb(bytes: Long) = bytes / 1_048_576

/**
 * Install / update / progress card for one downloadable bundle. Renders
 * nothing when the bundle is installed, current and idle.
 * [notInstalledHint] is shown with a Download button when nothing is installed
 * (null: the bundle always has a baseline, e.g. tools from the APK).
 */
@Composable
fun BundleUpdateCard(
    state: BundleState,
    notInstalledHint: String? = null,
    onDownload: () -> Unit,
    onCancel: () -> Unit,
    onApply: () -> Unit,
    onDismiss: () -> Unit,
) {
    val op = state.op
    val name = state.label
    val installed = state.installedVersion != null
    when {
        op.busy -> BundleCard(MaterialTheme.colorScheme.secondaryContainer, MaterialTheme.colorScheme.onSecondaryContainer) {
            val (label, progress) = when (op) {
                is BundleOp.Checking -> "Checking $name releases..." to null
                is BundleOp.Downloading -> "Downloading $name: ${mb(op.bytes)} / ${mb(op.total)} MB" to op.fraction()
                is BundleOp.Verifying -> "Verifying download..." to null
                is BundleOp.Installing -> "Installing $name..." to op.fraction()
                else -> "" to null
            }
            Text(label, style = MaterialTheme.typography.titleSmall)
            Spacer(Modifier.height(8.dp))
            if (progress != null) {
                LinearProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxWidth())
            } else {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
            Spacer(Modifier.height(8.dp))
            OutlinedButton(onClick = onCancel) { Text("Cancel") }
        }
        op is BundleOp.PendingSwap -> BundleCard(MaterialTheme.colorScheme.tertiaryContainer, MaterialTheme.colorScheme.onTertiaryContainer) {
            Text("$name ${op.version} is ready to install", style = MaterialTheme.typography.titleSmall)
            Text(op.reason, style = MaterialTheme.typography.bodySmall)
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = onApply) { Text("Install now") }
                OutlinedButton(onClick = onCancel) { Text("Discard") }
            }
        }
        op is BundleOp.Error -> BundleCard(MaterialTheme.colorScheme.errorContainer, MaterialTheme.colorScheme.onErrorContainer) {
            Text("$name update failed", style = MaterialTheme.typography.titleSmall)
            Text(op.message, style = MaterialTheme.typography.bodySmall)
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = onDownload) { Text("Retry") }
                OutlinedButton(onClick = onDismiss) { Text("Dismiss") }
            }
        }
        !installed && notInstalledHint != null -> BundleCard(MaterialTheme.colorScheme.secondaryContainer, MaterialTheme.colorScheme.onSecondaryContainer) {
            val size = state.downloadSize?.let { " (≈${mb(it)} MB)" } ?: ""
            Text("$name not installed", style = MaterialTheme.typography.titleSmall)
            Text(notInstalledHint, style = MaterialTheme.typography.bodySmall)
            Spacer(Modifier.height(8.dp))
            Button(onClick = onDownload) { Text("Download$size") }
        }
        // Only offer an update the last check actually found; a legacy install
        // with no published release has nothing to update to.
        state.availableVersion != null -> BundleCard(MaterialTheme.colorScheme.primaryContainer, MaterialTheme.colorScheme.onPrimaryContainer) {
            Text("Update available: ${state.availableVersion}", style = MaterialTheme.typography.titleSmall)
            val current = if (state.installedVersion == BundleVersions.LEGACY) "bundled with an older app" else state.installedVersion
            Text("Installed: $current" + (state.source?.let { " ($it)" } ?: ""), style = MaterialTheme.typography.bodySmall)
            state.downloadSize?.let { Text("Download ≈${mb(it)} MB", style = MaterialTheme.typography.bodySmall) }
            Spacer(Modifier.height(8.dp))
            Button(onClick = onDownload) { Text("Update") }
        }
    }
    state.message?.let { msg ->
        BundleCard(MaterialTheme.colorScheme.surfaceVariant, MaterialTheme.colorScheme.onSurfaceVariant) {
            Text(msg, style = MaterialTheme.typography.bodySmall)
            TextButton(onClick = onDismiss) { Text("OK") }
        }
    }
}

private fun BundleOp.Downloading.fraction() = if (total > 0) (bytes.toFloat() / total).coerceIn(0f, 1f) else 0f
private fun BundleOp.Installing.fraction() = if (total > 0) (bytes.toFloat() / total).coerceIn(0f, 1f) else 0f

@Composable
internal fun BundleCard(container: Color, content: Color, body: @Composable () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().padding(bottom = 4.dp),
        colors = CardDefaults.cardColors(containerColor = container, contentColor = content),
    ) {
        Column(modifier = Modifier.padding(16.dp)) { body() }
    }
}

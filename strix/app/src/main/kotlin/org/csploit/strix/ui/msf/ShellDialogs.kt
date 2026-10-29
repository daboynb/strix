package org.csploit.strix.ui.msf

import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap

@Composable
internal fun UploadDialog(
    sourcePath: String?,
    onConfirm: (remotePath: String) -> Unit,
    onDismiss: () -> Unit,
) {
    var remote by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Upload to victim") },
        text = {
            Column {
                Text(
                    "Source: ${sourcePath ?: "(picking...)"}",
                    style = MaterialTheme.typography.bodySmall,
                )
                OutlinedTextField(
                    value = remote,
                    onValueChange = { remote = it },
                    label = { Text("Remote path (blank = cwd with same name)") },
                    singleLine = true,
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(remote) },
                enabled = sourcePath != null,
            ) { Text("Upload") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

@Composable
internal fun DownloadDialog(
    onConfirm: (remotePath: String) -> Unit,
    onDismiss: () -> Unit,
) {
    var remote by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Download from victim") },
        text = {
            Column {
                Text(
                    "File lands in app files/msf_downloads/",
                    style = MaterialTheme.typography.bodySmall,
                )
                OutlinedTextField(
                    value = remote,
                    onValueChange = { remote = it },
                    label = { Text("Remote path") },
                    singleLine = true,
                )
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(remote) }) { Text("Download") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

@Composable
internal fun ScreenshotDialog(path: String, onDismiss: () -> Unit) {
    val bitmap = remember(path) { runCatching { BitmapFactory.decodeFile(path) }.getOrNull() }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Screenshot") },
        text = {
            if (bitmap != null) {
                Image(
                    bitmap = bitmap.asImageBitmap(),
                    contentDescription = "Screenshot",
                    modifier = Modifier.fillMaxWidth().fillMaxHeight(0.7f),
                )
            } else {
                Text("Failed to decode image at $path")
            }
        },
        confirmButton = {
            Button(onClick = onDismiss) { Text("Close") }
        },
    )
}

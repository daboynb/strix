package org.csploit.strix.ui.msf

import android.graphics.BitmapFactory
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ShellScreen(
    onBack: () -> Unit,
    viewModel: ShellViewModel = hiltViewModel(),
) {
    val uiState by viewModel.uiState.collectAsState()
    val listState = rememberLazyListState()

    LaunchedEffect(uiState.output.size) {
        if (uiState.output.isNotEmpty()) {
            listState.animateScrollToItem(uiState.output.size - 1)
        }
    }

    val filePicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri -> if (uri != null) viewModel.setUploadSource(uri) }

    val title = when (uiState.kind) {
        SessionKind.METERPRETER -> "Meterpreter #${uiState.sessionId}"
        SessionKind.SHELL -> "Shell #${uiState.sessionId}"
        else -> "Session #${uiState.sessionId}"
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(title) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color(0xFF1A1A2E),
                ),
            )
        },
        containerColor = Color(0xFF0D0D1A),
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            if (uiState.kind == SessionKind.METERPRETER) {
                MeterpreterQuickActions(
                    onAction = { cmd, prefill ->
                        if (prefill) viewModel.updateInput("$cmd ") else viewModel.send(cmd)
                    },
                    onUpload = {
                        viewModel.openUploadDialog()
                        filePicker.launch(arrayOf("*/*"))
                    },
                    onDownload = viewModel::openDownloadDialog,
                    onScreenshot = viewModel::takeScreenshot,
                )
            }

            LazyColumn(
                state = listState,
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .padding(horizontal = 8.dp, vertical = 4.dp),
            ) {
                items(uiState.output) { line ->
                    val color = when {
                        line.startsWith("$") -> Color(0xFF4FC3F7)
                        line.startsWith("[read error") -> Color(0xFFEF5350)
                        line.startsWith("[") -> Color(0xFFFFB74D)
                        else -> Color(0xFFE0E0E0)
                    }
                    Text(
                        line,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                        lineHeight = 16.sp,
                        color = color,
                    )
                }
            }

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(8.dp),
            ) {
                OutlinedTextField(
                    value = uiState.input,
                    onValueChange = viewModel::updateInput,
                    modifier = Modifier.weight(1f),
                    placeholder = { Text("command...") },
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodyMedium.copy(
                        fontFamily = FontFamily.Monospace,
                        color = Color(0xFFE0E0E0),
                    ),
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
                    keyboardActions = KeyboardActions(onSend = { viewModel.sendCommand() }),
                )
                IconButton(onClick = viewModel::sendCommand) {
                    Icon(
                        Icons.AutoMirrored.Filled.Send,
                        "Send",
                        tint = MaterialTheme.colorScheme.primary,
                    )
                }
            }
        }
    }

    when (val dlg = uiState.dialog) {
        is ShellDialog.Upload -> UploadDialog(
            sourcePath = dlg.sourcePath,
            onConfirm = viewModel::confirmUpload,
            onDismiss = viewModel::dismissDialog,
        )
        is ShellDialog.Download -> DownloadDialog(
            onConfirm = viewModel::confirmDownload,
            onDismiss = viewModel::dismissDialog,
        )
        is ShellDialog.ScreenshotPreview -> ScreenshotDialog(
            path = dlg.path,
            onDismiss = viewModel::dismissDialog,
        )
        null -> {}
    }
}

@Composable
private fun MeterpreterQuickActions(
    onAction: (cmd: String, prefill: Boolean) -> Unit,
    onUpload: () -> Unit,
    onDownload: () -> Unit,
    onScreenshot: () -> Unit,
) {
    val scrollState = rememberScrollState()
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(scrollState)
            .padding(horizontal = 8.dp, vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Chip("sysinfo") { onAction("sysinfo", false) }
        Chip("getuid") { onAction("getuid", false) }
        Chip("ps") { onAction("ps", false) }
        Chip("hashdump") { onAction("hashdump", false) }
        Chip("getsystem") { onAction("getsystem", false) }
        Chip("migrate <pid>") { onAction("migrate", true) }
        Chip("screenshot", onScreenshot)
        Chip("upload", onUpload)
        Chip("download", onDownload)
        Chip("shell") { onAction("shell", false) }
        Chip("ifconfig") { onAction("ifconfig", false) }
    }
}

@Composable
private fun Chip(label: String, onClick: () -> Unit) {
    AssistChip(
        onClick = onClick,
        label = { Text(label, fontSize = 12.sp) },
        colors = AssistChipDefaults.assistChipColors(
            containerColor = Color(0xFF1A1A2E),
            labelColor = Color(0xFF4FC3F7),
        ),
    )
}

@Composable
private fun UploadDialog(
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
private fun DownloadDialog(
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
private fun ScreenshotDialog(path: String, onDismiss: () -> Unit) {
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

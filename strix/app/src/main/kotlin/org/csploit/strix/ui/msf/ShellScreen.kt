package org.csploit.strix.ui.msf

import android.graphics.BitmapFactory
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
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
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import org.csploit.strix.ui.theme.StatusBarIcons

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
            StatusBarIcons(TerminalBar)
            TopAppBar(
                title = { Text(title) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back")
                    }
                },
                // Fixed terminal-dark bar: content colors must be light in
                // both themes, not the theme's onSurface.
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = TerminalBar,
                    titleContentColor = TerminalText,
                    navigationIconContentColor = TerminalText,
                    actionIconContentColor = TerminalText,
                ),
            )
        },
        containerColor = TerminalBackground,
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            uiState.error?.let { message ->
                ErrorBanner(
                    message = message,
                    onDismiss = if (uiState.sessionClosed) null else viewModel::clearError,
                )
            }

            if (uiState.kind == SessionKind.METERPRETER && !uiState.sessionClosed) {
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
                        line.startsWith("[read error") -> TerminalError
                        line.startsWith("[session ") -> TerminalError
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
                    enabled = !uiState.sessionClosed,
                    placeholder = {
                        Text(if (uiState.sessionClosed) "session closed" else "command...")
                    },
                    singleLine = true,
                    textStyle = MaterialTheme.typography.bodyMedium.copy(
                        fontFamily = FontFamily.Monospace,
                    ),
                    // Sits on the fixed dark background: theme defaults
                    // (onSurface/onSurfaceVariant) are unreadable in light theme.
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = TerminalText,
                        unfocusedTextColor = TerminalText,
                        disabledTextColor = TerminalMuted,
                        focusedPlaceholderColor = TerminalMuted,
                        unfocusedPlaceholderColor = TerminalMuted,
                        disabledPlaceholderColor = TerminalMuted,
                        cursorColor = TerminalAccent,
                        focusedBorderColor = TerminalAccent,
                        unfocusedBorderColor = TerminalMuted,
                        disabledBorderColor = TerminalMuted.copy(alpha = 0.4f),
                    ),
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
                    keyboardActions = KeyboardActions(onSend = { viewModel.sendCommand() }),
                )
                IconButton(
                    onClick = viewModel::sendCommand,
                    enabled = !uiState.sessionClosed,
                ) {
                    Icon(
                        Icons.AutoMirrored.Filled.Send,
                        "Send",
                        tint = if (uiState.sessionClosed) TerminalMuted else TerminalAccent,
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

private val TerminalBar = Color(0xFF1A1A2E)
private val TerminalBackground = Color(0xFF0D0D1A)
private val TerminalText = Color(0xFFE0E0E0)
private val TerminalMuted = Color(0xFF9E9EB0)
private val TerminalAccent = Color(0xFF4FC3F7)
private val TerminalError = Color(0xFFEF5350)

@Composable
private fun ErrorBanner(message: String, onDismiss: (() -> Unit)?) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(TerminalError.copy(alpha = 0.18f))
            .padding(start = 12.dp, end = 4.dp, top = 4.dp, bottom = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            message,
            modifier = Modifier.weight(1f),
            color = TerminalText,
            fontSize = 12.sp,
        )
        if (onDismiss != null) {
            IconButton(onClick = onDismiss) {
                Icon(Icons.Default.Close, "Dismiss", tint = TerminalText)
            }
        }
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

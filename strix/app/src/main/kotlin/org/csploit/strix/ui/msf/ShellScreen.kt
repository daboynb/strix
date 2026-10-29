package org.csploit.strix.ui.msf

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
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

            ShellOutput(uiState.output, listState, Modifier.weight(1f))

            ShellInputBar(
                input = uiState.input,
                sessionClosed = uiState.sessionClosed,
                onInputChange = viewModel::updateInput,
                onSend = viewModel::sendCommand,
            )
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

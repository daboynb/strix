package org.csploit.strix.ui.bruteforce

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

@Composable
fun BruteForceScreen(
    onBack: () -> Unit,
    viewModel: BruteForceViewModel = hiltViewModel(),
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val listState = rememberLazyListState()

    // Auto-scroll log to bottom
    LaunchedEffect(uiState.logLines.size) {
        if (uiState.logLines.isNotEmpty()) {
            listState.animateScrollToItem(uiState.logLines.size - 1)
        }
    }

    Scaffold(
        topBar = {
            BruteForceTopBar(
                title = "${viewModel.ip}:${viewModel.port}",
                isRunning = uiState.isRunning,
                onBack = onBack,
                onStart = { viewModel.start() },
                onStop = { viewModel.stop() },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            // Config section
            ConfigSection(
                method = uiState.method,
                path = uiState.path,
                methods = uiState.methods,
                enabled = !uiState.isRunning,
                onMethodChange = { viewModel.setMethod(it) },
                onPathChange = { viewModel.setPath(it) },
            )

            // Wordlists + password mode
            WordlistsSection(
                state = uiState,
                enabled = !uiState.isRunning,
                onPickUsers = { viewModel.pickUsersFile(it) },
                onPickPasswords = { viewModel.pickPasswordsFile(it) },
                onClearUsers = { viewModel.clearCustomUsers() },
                onClearPasswords = { viewModel.clearCustomPasswords() },
                onModeChange = { viewModel.setPasswordMode(it) },
                onCharsetChange = { l, u, d -> viewModel.setCharset(l, u, d) },
                onRangeChange = { min, max -> viewModel.setPassRange(min, max) },
            )

            BruteForceStatus(uiState)

            // Log output (takes remaining space, doesn't push other widgets out)
            BruteForceLogList(uiState.logLines, listState)
        }
    }
}

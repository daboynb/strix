package org.csploit.strix.ui.bruteforce

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlin.math.roundToInt

@OptIn(ExperimentalMaterial3Api::class)
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
            TopAppBar(
                title = { Text("${viewModel.ip}:${viewModel.port}") },
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

            // Progress bar
            uiState.progress?.let { p ->
                LinearProgressIndicator(
                    progress = { p },
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp),
                )
            }
            uiState.statusLine?.let { line ->
                Text(
                    line,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 2.dp),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 10.sp,
                )
            }

            // Found credentials banner
            uiState.foundCreds?.let { creds ->
                Text(
                    "FOUND: $creds",
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(MaterialTheme.colorScheme.errorContainer)
                        .padding(12.dp),
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.titleSmall,
                )
            }

            // Log output (takes remaining space, doesn't push other widgets out)
            LazyColumn(
                state = listState,
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .background(MaterialTheme.colorScheme.surfaceContainerLowest)
                    .padding(8.dp),
            ) {
                items(uiState.logLines) { line ->
                    Text(
                        line,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        color = when {
                            line.contains("login:") -> MaterialTheme.colorScheme.error
                            line.startsWith("[") -> MaterialTheme.colorScheme.tertiary
                            else -> MaterialTheme.colorScheme.onSurface
                        },
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ConfigSection(
    method: String,
    path: String,
    methods: List<String>,
    enabled: Boolean,
    onMethodChange: (String) -> Unit,
    onPathChange: (String) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }

    Row(
        modifier = Modifier.fillMaxWidth().padding(8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        ExposedDropdownMenuBox(
            expanded = expanded,
            onExpandedChange = { if (enabled) expanded = it },
            modifier = Modifier.weight(1f),
        ) {
            OutlinedTextField(
                value = method,
                onValueChange = {},
                readOnly = true,
                enabled = enabled,
                label = { Text("Method") },
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded) },
                modifier = Modifier.menuAnchor(),
            )
            ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                methods.forEach { m ->
                    DropdownMenuItem(
                        text = { Text(m) },
                        onClick = { onMethodChange(m); expanded = false },
                    )
                }
            }
        }

        OutlinedTextField(
            value = path,
            onValueChange = onPathChange,
            enabled = enabled,
            label = { Text("Path") },
            modifier = Modifier.weight(1f),
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun WordlistsSection(
    state: BruteForceUiState,
    enabled: Boolean,
    onPickUsers: (android.net.Uri) -> Unit,
    onPickPasswords: (android.net.Uri) -> Unit,
    onClearUsers: () -> Unit,
    onClearPasswords: () -> Unit,
    onModeChange: (PasswordMode) -> Unit,
    onCharsetChange: (lower: Boolean, upper: Boolean, digits: Boolean) -> Unit,
    onRangeChange: (min: Int, max: Int) -> Unit,
) {
    val usersLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri -> uri?.let(onPickUsers) }
    val passwordsLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri -> uri?.let(onPickPasswords) }

    Column(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        // Users wordlist
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedButton(
                onClick = { usersLauncher.launch(arrayOf("*/*")) },
                enabled = enabled,
                modifier = Modifier.weight(1f),
            ) {
                Icon(Icons.Default.FileOpen, null, modifier = Modifier.width(16.dp))
                Spacer(Modifier.width(4.dp))
                Text(
                    state.customUsersPath?.substringAfterLast('/') ?: "Users: default",
                    maxLines = 1,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (state.customUsersPath != null) {
                IconButton(onClick = onClearUsers, enabled = enabled) {
                    Icon(Icons.Default.Clear, "Reset users wordlist")
                }
            }
        }

        // Password source toggle
        SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
            SegmentedButton(
                selected = state.passwordMode == PasswordMode.WORDLIST,
                onClick = { onModeChange(PasswordMode.WORDLIST) },
                enabled = enabled,
                shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2),
            ) { Text("Wordlist") }
            SegmentedButton(
                selected = state.passwordMode == PasswordMode.CHARSET,
                onClick = { onModeChange(PasswordMode.CHARSET) },
                enabled = enabled,
                shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2),
            ) { Text("Charset") }
        }

        if (state.passwordMode == PasswordMode.WORDLIST) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedButton(
                    onClick = { passwordsLauncher.launch(arrayOf("*/*")) },
                    enabled = enabled,
                    modifier = Modifier.weight(1f),
                ) {
                    Icon(Icons.Default.FileOpen, null, modifier = Modifier.width(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text(
                        state.customPasswordsPath?.substringAfterLast('/') ?: "Passwords: default",
                        maxLines = 1,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                if (state.customPasswordsPath != null) {
                    IconButton(onClick = onClearPasswords, enabled = enabled) {
                        Icon(Icons.Default.Clear, "Reset passwords wordlist")
                    }
                }
            }
        } else {
            // Charset + length
            Row(
                horizontalArrangement = Arrangement.spacedBy(4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                FilterChip(
                    selected = state.charsetLower,
                    onClick = {
                        onCharsetChange(!state.charsetLower, state.charsetUpper, state.charsetDigits)
                    },
                    label = { Text("a-z") },
                    enabled = enabled,
                )
                FilterChip(
                    selected = state.charsetUpper,
                    onClick = {
                        onCharsetChange(state.charsetLower, !state.charsetUpper, state.charsetDigits)
                    },
                    label = { Text("A-Z") },
                    enabled = enabled,
                )
                FilterChip(
                    selected = state.charsetDigits,
                    onClick = {
                        onCharsetChange(state.charsetLower, state.charsetUpper, !state.charsetDigits)
                    },
                    label = { Text("0-9") },
                    enabled = enabled,
                )
            }
            Column {
                Text("Min length: ${state.passMin}", style = MaterialTheme.typography.labelSmall)
                Slider(
                    value = state.passMin.toFloat(),
                    onValueChange = { onRangeChange(it.roundToInt(), state.passMax) },
                    valueRange = 1f..8f,
                    steps = 6,
                    enabled = enabled,
                )
                Text("Max length: ${state.passMax}", style = MaterialTheme.typography.labelSmall)
                Slider(
                    value = state.passMax.toFloat(),
                    onValueChange = { onRangeChange(state.passMin, it.roundToInt()) },
                    valueRange = 1f..8f,
                    steps = 6,
                    enabled = enabled,
                )
            }
        }
    }
}

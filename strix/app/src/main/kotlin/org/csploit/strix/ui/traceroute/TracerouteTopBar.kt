package org.csploit.strix.ui.traceroute

import androidx.compose.foundation.layout.Column
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import org.csploit.strix.ui.theme.StatusBarIcons

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun TracerouteTopBar(
    ip: String,
    isTracing: Boolean,
    onBack: () -> Unit,
    onStart: () -> Unit,
    onStop: () -> Unit,
) {
    StatusBarIcons(MaterialTheme.colorScheme.primaryContainer)
    TopAppBar(
        title = {
            Column {
                Text("Traceroute")
                Text(
                    ip,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        },
        navigationIcon = {
            IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
            }
        },
        actions = {
            if (isTracing) {
                IconButton(onClick = onStop) {
                    Icon(Icons.Default.Stop, contentDescription = "Stop")
                }
            } else {
                IconButton(onClick = onStart) {
                    Icon(Icons.Default.PlayArrow, contentDescription = "Trace")
                }
            }
        },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer,
            titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
            navigationIconContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
            actionIconContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
        ),
    )
}

package org.csploit.strix.ui.packetforger

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.csploit.strix.ui.theme.StatusBarIcons

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun PacketForgerTopBar(
    ip: String,
    isSending: Boolean,
    onBack: () -> Unit,
    onSend: () -> Unit,
) {
    StatusBarIcons(MaterialTheme.colorScheme.primaryContainer)
    TopAppBar(
        title = {
            Column {
                Text("Packet Forger")
                Text(ip, style = MaterialTheme.typography.bodySmall)
            }
        },
        navigationIcon = {
            IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
            }
        },
        actions = {
            if (isSending) {
                CircularProgressIndicator(
                    modifier = Modifier.padding(12.dp),
                    strokeWidth = 2.dp,
                )
            } else {
                IconButton(onClick = onSend) {
                    Icon(Icons.AutoMirrored.Filled.Send, contentDescription = "Send")
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

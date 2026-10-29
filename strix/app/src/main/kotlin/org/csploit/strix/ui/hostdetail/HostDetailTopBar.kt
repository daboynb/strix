package org.csploit.strix.ui.hostdetail

import androidx.compose.foundation.layout.Column
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import org.csploit.strix.ui.theme.StatusBarIcons

/** Title = host name (or IP); subtitle = IP • MAC • manufacturer when known. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun HostDetailTopBar(
    ip: String,
    hostName: String?,
    mac: String?,
    manufacturer: String?,
    onBack: () -> Unit,
) {
    StatusBarIcons(MaterialTheme.colorScheme.primaryContainer)
    TopAppBar(
        title = {
            Column {
                Text(hostName ?: ip)
                Text(
                    buildString {
                        append(ip)
                        mac?.let { append(" • $it") }
                        manufacturer?.let { append(" • $it") }
                    },
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        },
        navigationIcon = {
            IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
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

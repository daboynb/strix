package org.csploit.strix.ui.hostdetail

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp

data class ActionItem(
    val icon: ImageVector,
    val label: String,
    val enabled: Boolean = true,
    val onClick: () -> Unit,
)

@Composable
internal fun ActionCard(action: ActionItem) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .height(100.dp)
            .then(if (action.enabled) Modifier.clickable(onClick = action.onClick) else Modifier),
        colors = CardDefaults.cardColors(
            containerColor = if (action.enabled)
                MaterialTheme.colorScheme.secondaryContainer
            else
                MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
        ),
    ) {
        Column(
            modifier = Modifier.fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(
                action.icon,
                contentDescription = action.label,
                modifier = Modifier.size(32.dp),
                tint = if (action.enabled)
                    MaterialTheme.colorScheme.onSecondaryContainer
                else
                    MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
            )
            Spacer(Modifier.height(8.dp))
            Text(
                action.label,
                style = MaterialTheme.typography.labelLarge,
                color = if (action.enabled)
                    MaterialTheme.colorScheme.onSecondaryContainer
                else
                    MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
            )
        }
    }
}

package org.csploit.strix.ui.logs

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/** Level filter chips and the search field above the log. */
@Composable
internal fun LogsFilterBar(
    filter: LevelFilter,
    query: String,
    onFilter: (LevelFilter) -> Unit,
    onQuery: (String) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        LevelFilter.entries.forEach { f ->
            FilterChip(
                selected = filter == f,
                onClick = { onFilter(f) },
                label = { Text(f.label) },
            )
        }
    }
    OutlinedTextField(
        value = query,
        onValueChange = onQuery,
        placeholder = { Text("Search") },
        leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
        trailingIcon = {
            if (query.isNotEmpty()) {
                IconButton(onClick = { onQuery("") }) {
                    Icon(Icons.Default.Clear, contentDescription = "Clear search")
                }
            }
        },
        singleLine = true,
        modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp),
    )
}

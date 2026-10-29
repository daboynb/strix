package org.csploit.strix.ui.bruteforce

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun ConfigSection(
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

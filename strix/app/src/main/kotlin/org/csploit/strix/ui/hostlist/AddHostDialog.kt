package org.csploit.strix.ui.hostlist

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
internal fun AddHostDialog(
    onDismiss: () -> Unit,
    onAdd: (ip: String, name: String?) -> Unit,
) {
    var ip by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    val ipValid = ip.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")) ||
        ip.matches(Regex("^[a-zA-Z0-9][a-zA-Z0-9._-]*\\.[a-zA-Z]{2,}$"))

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Add Target") },
        text = {
            Column {
                OutlinedTextField(
                    value = ip,
                    onValueChange = { ip = it.trim() },
                    label = { Text("IP or hostname") },
                    singleLine = true,
                    isError = ip.isNotEmpty() && !ipValid,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Label (optional)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onAdd(ip, name.ifBlank { null }) },
                enabled = ipValid,
            ) { Text("Add") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

package org.csploit.strix.ui.msf

import org.csploit.strix.domain.model.MsfSession

data class MsfUiState(
    val msfInstalled: Boolean = false,
    val isConnected: Boolean = false,
    val msfVersion: String? = null,
    val sessions: List<MsfSession> = emptyList(),
    val error: String? = null,
    val connecting: Boolean = false,
)

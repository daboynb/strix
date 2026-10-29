package org.csploit.strix.ui.packetforger

enum class Protocol { TCP, UDP }

data class PacketForgerUiState(
    val protocol: Protocol = Protocol.TCP,
    val port: String = "80",
    val payload: String = "",
    val waitResponse: Boolean = true,
    val isSending: Boolean = false,
    val response: String? = null,
    val error: String? = null,
)

package org.csploit.strix.ui.packetforger

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.csploit.strix.data.PacketForger
import javax.inject.Inject

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

@HiltViewModel
class PacketForgerViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val packetForger: PacketForger,
) : ViewModel() {

    val ip: String = savedStateHandle["ip"] ?: ""
    val mac: String? = savedStateHandle.get<String>("mac")?.takeIf { it.isNotEmpty() && it != "00:00:00:00:00:00" }

    private val _uiState = MutableStateFlow(PacketForgerUiState())
    val uiState: StateFlow<PacketForgerUiState> = _uiState.asStateFlow()

    private var sendJob: Job? = null

    fun setProtocol(p: Protocol) {
        _uiState.value = _uiState.value.copy(protocol = p)
    }

    fun setPort(port: String) {
        _uiState.value = _uiState.value.copy(port = port)
    }

    fun setPayload(payload: String) {
        _uiState.value = _uiState.value.copy(payload = payload)
    }

    fun setWaitResponse(wait: Boolean) {
        _uiState.value = _uiState.value.copy(waitResponse = wait)
    }

    fun send() {
        val state = _uiState.value
        val port = state.port.toIntOrNull()
        if (port == null || port !in 1..65535) {
            _uiState.value = state.copy(error = "Invalid port (1-65535)")
            return
        }
        if (state.payload.isBlank()) {
            _uiState.value = state.copy(error = "Payload is empty")
            return
        }

        sendJob?.cancel()
        _uiState.value = state.copy(isSending = true, response = null, error = null)

        val data = state.payload
            .replace("\\r", "\r")
            .replace("\\n", "\n")
            .replace("\\t", "\t")
            .toByteArray()

        sendJob = viewModelScope.launch {
            val result = when (state.protocol) {
                Protocol.TCP -> packetForger.sendTcp(ip, port, data, state.waitResponse)
                Protocol.UDP -> packetForger.sendUdp(ip, port, data, state.waitResponse)
            }
            _uiState.value = _uiState.value.copy(
                isSending = false,
                response = result.response,
                error = result.error,
            )
        }
    }

    fun sendWol() {
        val macAddr = mac ?: return
        _uiState.value = _uiState.value.copy(
            protocol = Protocol.UDP,
            port = "9",
            payload = wolPayloadHex(macAddr),
            waitResponse = false,
        )

        sendJob?.cancel()
        _uiState.value = _uiState.value.copy(isSending = true, response = null, error = null)

        val data = packetForger.buildWolPacket(macAddr)

        sendJob = viewModelScope.launch {
            val result = packetForger.sendUdp(ip, 9, data, waitResponse = false)
            _uiState.value = _uiState.value.copy(
                isSending = false,
                response = if (result.success) "WoL packet sent" else null,
                error = result.error,
            )
        }
    }

    fun stop() {
        sendJob?.cancel()
        sendJob = null
        _uiState.value = _uiState.value.copy(isSending = false)
    }

    private fun wolPayloadHex(mac: String): String {
        val m = mac.replace(":", "")
        return "FF".repeat(6) + m.uppercase().repeat(16)
    }

    override fun onCleared() {
        super.onCleared()
        sendJob?.cancel()
    }
}

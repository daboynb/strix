package org.csploit.strix.ui.msf

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import org.csploit.strix.data.AppSettings
import org.csploit.strix.data.DaemonState
import org.csploit.strix.data.MsfDaemon
import org.csploit.strix.data.MsfRpcClient
import org.csploit.strix.data.ToolManager
import org.csploit.strix.domain.model.MsfSession
import javax.inject.Inject

data class MsfUiState(
    val msfInstalled: Boolean = false,
    val isConnected: Boolean = false,
    val msfVersion: String? = null,
    val sessions: List<MsfSession> = emptyList(),
    val error: String? = null,
    val connecting: Boolean = false,
)

@HiltViewModel
class MsfViewModel @Inject constructor(
    private val msfDaemon: MsfDaemon,
    private val rpcClient: MsfRpcClient,
    private val toolManager: ToolManager,
    private val appSettings: AppSettings,
) : ViewModel() {

    private val _uiState = MutableStateFlow(MsfUiState())
    val uiState: StateFlow<MsfUiState> = _uiState.asStateFlow()

    val daemonState: StateFlow<DaemonState> = msfDaemon.state
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), DaemonState.STOPPED)

    val daemonLogs: StateFlow<List<String>> = msfDaemon.logs
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    init {
        _uiState.value = _uiState.value.copy(
            msfInstalled = toolManager.isMsfInstalled(),
            isConnected = rpcClient.isAuthenticated,
        )
    }

    fun startDaemon() {
        viewModelScope.launch {
            try {
                _uiState.value = _uiState.value.copy(error = null)
                msfDaemon.start()
                if (msfDaemon.isRunning) {
                    // Daemon.start() already authenticated via RPC polling
                    val version = try {
                        val v = rpcClient.coreVersion()
                        "${v["version"] ?: "unknown"} (API: ${v["api"] ?: "?"})"
                    } catch (_: Exception) { null }

                    _uiState.value = _uiState.value.copy(
                        isConnected = true,
                        msfVersion = version,
                    )
                    refreshSessions()
                }
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = "Daemon start failed: ${e.message}")
            }
        }
    }

    fun stopDaemon() {
        msfDaemon.stop()
        rpcClient.disconnect()
        _uiState.value = _uiState.value.copy(
            isConnected = false,
            msfVersion = null,
            sessions = emptyList(),
        )
    }

    fun connectToRpc() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(connecting = true, error = null)
            try {
                rpcClient.configure(
                    host = appSettings.msfRpcHost,
                    port = appSettings.msfRpcPort,
                    ssl = appSettings.msfRpcSsl,
                )
                rpcClient.login(appSettings.msfRpcUser, appSettings.msfRpcPassword)

                val version = try {
                    val v = rpcClient.coreVersion()
                    "${v["version"] ?: "unknown"} (API: ${v["api"] ?: "?"})"
                } catch (_: Exception) { null }

                _uiState.value = _uiState.value.copy(
                    isConnected = true,
                    connecting = false,
                    msfVersion = version,
                )

                refreshSessions()
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(
                    connecting = false,
                    error = "Connection failed: ${e.message}",
                )
            }
        }
    }

    fun refreshSessions() {
        viewModelScope.launch {
            try {
                val sessions = rpcClient.sessionList()
                _uiState.value = _uiState.value.copy(sessions = sessions)
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = "Session refresh failed: ${e.message}")
            }
        }
    }

    fun stopSession(sessionId: Int) {
        viewModelScope.launch {
            try {
                rpcClient.sessionStop(sessionId)
                refreshSessions()
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = "Stop session failed: ${e.message}")
            }
        }
    }
}

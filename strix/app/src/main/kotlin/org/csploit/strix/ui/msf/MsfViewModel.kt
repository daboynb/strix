package org.csploit.strix.ui.msf

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.csploit.strix.data.AppSettings
import org.csploit.strix.data.DaemonState
import org.csploit.strix.data.MsfDaemon
import org.csploit.strix.data.MsfRpcClient
import org.csploit.strix.data.ToolManager
import org.csploit.strix.data.bundle.BundleState
import org.csploit.strix.data.bundle.BundleUpdateManager
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
    bundleUpdates: BundleUpdateManager,
) : ViewModel() {

    private val _uiState = MutableStateFlow(MsfUiState())
    val uiState: StateFlow<MsfUiState> = _uiState.asStateFlow()

    val daemonState: StateFlow<DaemonState> = msfDaemon.state
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), DaemonState.STOPPED)

    val daemonLogs: StateFlow<List<String>> = msfDaemon.logs
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    /** Install/update state of the downloadable Metasploit bundle. */
    private val bundleManager = bundleUpdates.msf
    val bundleState: StateFlow<BundleState> = bundleManager.state

    init {
        bundleManager.refreshInstalled()
        _uiState.value = _uiState.value.copy(
            msfInstalled = toolManager.isMsfInstalled(),
            isConnected = rpcClient.isAuthenticated,
        )
        // Follow installs/updates finishing while the screen is open.
        viewModelScope.launch {
            bundleManager.state
                .map { it.installedVersion }
                .distinctUntilChanged()
                .collect { _uiState.update { s -> s.copy(msfInstalled = toolManager.isMsfInstalled()) } }
        }
        // The daemon's startup runs in its own scope and may have been kicked
        // off by another screen (or a previous instance of this one), so
        // follow its state instead of only the result of our own start() call.
        viewModelScope.launch {
            msfDaemon.state.collect { state ->
                when (state) {
                    DaemonState.READY -> if (rpcClient.isAuthenticated && !_uiState.value.isConnected) {
                        onDaemonConnected()
                    }
                    DaemonState.STOPPED, DaemonState.FAILED -> _uiState.update {
                        it.copy(isConnected = false, msfVersion = null, sessions = emptyList())
                    }
                    DaemonState.STARTING -> {}
                }
            }
        }
    }

    private suspend fun onDaemonConnected() {
        // Daemon.start() already authenticated via RPC polling
        val version = try {
            val v = rpcClient.coreVersion()
            "${v["version"] ?: "unknown"} (API: ${v["api"] ?: "?"})"
        } catch (_: Exception) { null }

        _uiState.update { it.copy(isConnected = true, msfVersion = version) }
        refreshSessions()
    }

    fun startDaemon() {
        viewModelScope.launch {
            try {
                _uiState.update { it.copy(error = null) }
                // Connection state is picked up by the state collector in init.
                msfDaemon.start()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                _uiState.update { it.copy(error = "Daemon start failed: ${e.message}") }
            }
        }
    }

    fun downloadMsf() = bundleManager.install(force = false)

    fun cancelBundleOp() = bundleManager.cancel()

    fun applyPendingUpdate() = bundleManager.applyPending()

    fun dismissBundleMessage() = bundleManager.dismissMessage()

    fun stopDaemon() {
        // Non-blocking: MsfDaemon disconnects RPC and kills msfrpcd on its own IO scope.
        msfDaemon.stop()
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

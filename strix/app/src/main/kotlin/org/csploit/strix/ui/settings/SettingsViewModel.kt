package org.csploit.strix.ui.settings

import androidx.lifecycle.ViewModel
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.csploit.strix.core.ScanRegistry
import org.csploit.strix.data.AppSettings
import org.csploit.strix.data.ToolManager
import org.csploit.strix.data.bundle.BundleState
import org.csploit.strix.data.bundle.BundleUpdateManager
import org.csploit.strix.domain.model.ExtractionState
import javax.inject.Inject

@HiltViewModel
class SettingsViewModel @Inject constructor(
    private val appSettings: AppSettings,
    private val toolManager: ToolManager,
    private val bundleUpdates: BundleUpdateManager,
    private val scanRegistry: ScanRegistry,
) : ViewModel() {

    private val _uiState = MutableStateFlow(loadState())
    val uiState: StateFlow<SettingsUiState> = _uiState.asStateFlow()

    val msfBundleState: StateFlow<BundleState> = bundleUpdates.msf.state
    val toolsBundleState: StateFlow<BundleState> = bundleUpdates.tools.state
    val checkingUpdates: StateFlow<Boolean> = bundleUpdates.checking

    init {
        bundleUpdates.refreshInstalled()
    }

    fun setBundleWifiOnly(value: Boolean) {
        appSettings.bundleWifiOnly = value
        _uiState.update { it.copy(bundleWifiOnly = value) }
    }

    fun checkForUpdates() = bundleUpdates.checkForUpdates()

    fun dismissBundleMessages() = bundleUpdates.channels.forEach { it.dismissMessage() }

    fun downloadTools() = bundleUpdates.tools.install(force = false)

    fun cancelTools() = bundleUpdates.tools.cancel()

    fun applyPendingTools() = bundleUpdates.tools.applyPending()

    fun dismissToolsMessage() = bundleUpdates.tools.dismissMessage()

    /** Re-extract the tools bundle shipped in the APK (replaces a downloaded one). Runs app-scoped so leaving the screen doesn't abort it. */
    fun reinstallTools() {
        if (_uiState.value.reinstallingTools) return
        if (scanRegistry.activeTasks.value.isNotEmpty()) {
            _uiState.update { it.copy(toolsMessage = "Stop running scans first") }
            return
        }
        _uiState.update { it.copy(reinstallingTools = true, toolsMessage = null) }
        scanRegistry.appScope.launch {
            toolManager.extractTools(force = true)
            val result = toolManager.state.value
            bundleUpdates.tools.refreshInstalled()
            _uiState.update {
                it.copy(
                    reinstallingTools = false,
                    toolsMessage = if (result is ExtractionState.Error) result.message else "Tools reinstalled",
                )
            }
        }
    }

    fun setNmapTiming(value: Int) {
        appSettings.nmapTiming = value
        _uiState.value = _uiState.value.copy(nmapTiming = value)
    }

    fun setHydraThreads(value: Int) {
        appSettings.hydraThreads = value
        _uiState.value = _uiState.value.copy(hydraThreads = value)
    }

    fun setDefaultPortRange(value: String) {
        appSettings.defaultPortRange = value
        _uiState.value = _uiState.value.copy(defaultPortRange = value)
    }

    fun setSocketTimeout(value: Int) {
        appSettings.socketTimeoutSec = value
        _uiState.value = _uiState.value.copy(socketTimeoutSec = value)
    }

    fun setDnsServer(value: String) {
        appSettings.dnsServer = value
        _uiState.value = _uiState.value.copy(dnsServer = value)
    }

    fun setCustomNmapArgs(value: String) {
        appSettings.customNmapArgs = value
        _uiState.value = _uiState.value.copy(customNmapArgs = value)
    }

    private fun loadState() = SettingsUiState(
        nmapTiming = appSettings.nmapTiming,
        hydraThreads = appSettings.hydraThreads,
        defaultPortRange = appSettings.defaultPortRange,
        socketTimeoutSec = appSettings.socketTimeoutSec,
        dnsServer = appSettings.dnsServer,
        customNmapArgs = appSettings.customNmapArgs,
        bundleWifiOnly = appSettings.bundleWifiOnly,
    )
}

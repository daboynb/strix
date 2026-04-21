package org.csploit.strix.ui.settings

import androidx.lifecycle.ViewModel
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.csploit.strix.data.AppSettings
import javax.inject.Inject

data class SettingsUiState(
    val nmapTiming: Int = 4,
    val hydraThreads: Int = 4,
    val defaultPortRange: String = "",
    val socketTimeoutSec: Int = 5,
    val dnsServer: String = "",
    val customNmapArgs: String = "",
)

@HiltViewModel
class SettingsViewModel @Inject constructor(
    private val appSettings: AppSettings,
) : ViewModel() {

    private val _uiState = MutableStateFlow(loadState())
    val uiState: StateFlow<SettingsUiState> = _uiState.asStateFlow()

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
    )
}

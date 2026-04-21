package org.csploit.strix.ui.wifikeygen

import android.content.Context
import android.net.wifi.ScanResult
import android.net.wifi.WifiManager
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.csploit.strix.data.wifi.Keygen
import org.csploit.strix.data.wifi.WirelessMatcher
import javax.inject.Inject

data class WifiNetwork(
    val ssid: String,
    val bssid: String,
    val level: Int,
    val encryption: String,
    val frequency: Int,
    val hasKeygen: Boolean,
    val keys: List<String>? = null,
    val error: String? = null,
    val isGenerating: Boolean = false,
)

data class WifiKeygenUiState(
    val isScanning: Boolean = false,
    val networks: List<WifiNetwork> = emptyList(),
    val error: String? = null,
)

@HiltViewModel
class WifiKeygenViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
) : ViewModel() {

    private val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
    private val matcher = WirelessMatcher.fromXml(context.assets.open("alice.xml"))

    private val _uiState = MutableStateFlow(WifiKeygenUiState())
    val uiState: StateFlow<WifiKeygenUiState> = _uiState.asStateFlow()

    private var generateJob: Job? = null

    fun scan() {
        _uiState.value = _uiState.value.copy(isScanning = true, error = null)

        @Suppress("DEPRECATION")
        wifiManager.startScan()

        viewModelScope.launch {
            // Small delay to let scan results populate
            kotlinx.coroutines.delay(2000)
            loadResults()
        }
    }

    private fun loadResults() {
        @Suppress("DEPRECATION")
        val results = wifiManager.scanResults ?: emptyList()

        val seen = mutableSetOf<String>()
        val networks = results
            .filter { it.BSSID != null && seen.add(it.BSSID) }
            .sortedByDescending { it.level }
            .map { result ->
                val ssid = result.SSID ?: ""
                val bssid = result.BSSID ?: ""
                val enc = getSecurity(result)
                val keygen = matcher.getKeygen(ssid, bssid, result.level, enc)
                WifiNetwork(
                    ssid = ssid,
                    bssid = bssid,
                    level = WifiManager.calculateSignalLevel(result.level, 5),
                    encryption = enc,
                    frequency = result.frequency,
                    hasKeygen = keygen != null,
                )
            }

        _uiState.value = _uiState.value.copy(isScanning = false, networks = networks)
    }

    fun generateKeys(bssid: String) {
        val network = _uiState.value.networks.find { it.bssid == bssid } ?: return
        val keygen = matcher.getKeygen(network.ssid, network.bssid, network.level, network.encryption) ?: return

        updateNetwork(bssid) { it.copy(isGenerating = true, keys = null, error = null) }

        generateJob = viewModelScope.launch {
            val keys = withContext(Dispatchers.Default) {
                try {
                    keygen.getKeys()
                } catch (e: Exception) {
                    null
                }
            }
            updateNetwork(bssid) {
                it.copy(
                    isGenerating = false,
                    keys = keys?.takeIf { k -> k.isNotEmpty() },
                    error = if (keys.isNullOrEmpty()) "No keys found" else null,
                )
            }
        }
    }

    private fun updateNetwork(bssid: String, transform: (WifiNetwork) -> WifiNetwork) {
        _uiState.value = _uiState.value.copy(
            networks = _uiState.value.networks.map {
                if (it.bssid == bssid) transform(it) else it
            },
        )
    }

    private fun getSecurity(result: ScanResult): String {
        val cap = result.capabilities ?: ""
        return when {
            cap.contains("WPA2") -> "WPA2"
            cap.contains("WPA") -> "WPA"
            cap.contains("WEP") -> "WEP"
            else -> "Open"
        }
    }

    override fun onCleared() {
        super.onCleared()
        generateJob?.cancel()
    }
}

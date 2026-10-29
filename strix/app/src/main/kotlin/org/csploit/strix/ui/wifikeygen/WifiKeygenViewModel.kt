package org.csploit.strix.ui.wifikeygen

import android.content.Context
import android.net.wifi.WifiManager
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.csploit.strix.data.wifi.Keygen
import org.csploit.strix.data.wifi.WirelessMatcher
import javax.inject.Inject

@HiltViewModel
class WifiKeygenViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
) : ViewModel() {

    private val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
    private val matcher = WirelessMatcher.fromXml(context.assets.open("alice.xml"))

    private val _uiState = MutableStateFlow(WifiKeygenUiState())
    val uiState: StateFlow<WifiKeygenUiState> = _uiState.asStateFlow()

    private var generateJob: Job? = null
    private var generatingBssid: String? = null

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

        // One generation at a time: stop the previous one (e.g. Thomson's ~24M
        // SHA-1 brute force) and clear its spinner if it was another network.
        generateJob?.cancel()
        generatingBssid?.takeIf { it != bssid }?.let { previous ->
            updateNetwork(previous) { it.copy(isGenerating = false) }
        }
        generatingBssid = bssid
        updateNetwork(bssid) { it.copy(isGenerating = true, keys = null, error = null) }

        generateJob = viewModelScope.launch {
            // getKeys() is blocking and doesn't observe coroutine cancellation:
            // translate cancellation (new tap, leaving the screen) into the
            // keygen's cooperative stopRequested flag, checked by long loops.
            val stopper = launch(start = CoroutineStart.UNDISPATCHED) {
                try {
                    awaitCancellation()
                } finally {
                    keygen.stopRequested = true
                }
            }
            val outcome = try {
                withContext(Dispatchers.Default) { runCatching { keygen.getKeys() } }
            } finally {
                stopper.cancel()
            }
            val keys = outcome.getOrNull()?.takeIf { it.isNotEmpty() }
            val error = when {
                keys != null -> null
                outcome.isFailure -> outcome.exceptionOrNull()?.message ?: "Key generation failed"
                else -> keygen.errorMessage ?: "No keys found"
            }
            if (generatingBssid == bssid) generatingBssid = null
            updateNetwork(bssid) { it.copy(isGenerating = false, keys = keys, error = error) }
        }
    }

    private fun updateNetwork(bssid: String, transform: (WifiNetwork) -> WifiNetwork) {
        _uiState.value = _uiState.value.copy(
            networks = _uiState.value.networks.map {
                if (it.bssid == bssid) transform(it) else it
            },
        )
    }

    override fun onCleared() {
        super.onCleared()
        generateJob?.cancel()
    }
}

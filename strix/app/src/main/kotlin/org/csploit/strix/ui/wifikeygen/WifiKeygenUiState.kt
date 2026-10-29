package org.csploit.strix.ui.wifikeygen

import android.net.wifi.ScanResult

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

/** Encryption label shown for a scan result (and fed to the keygen matcher). */
internal fun getSecurity(result: ScanResult): String {
    val cap = result.capabilities ?: ""
    return when {
        cap.contains("WPA2") -> "WPA2"
        cap.contains("WPA") -> "WPA"
        cap.contains("WEP") -> "WEP"
        else -> "Open"
    }
}

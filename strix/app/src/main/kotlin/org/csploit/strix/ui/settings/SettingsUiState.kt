package org.csploit.strix.ui.settings

data class SettingsUiState(
    val nmapTiming: Int = 4,
    val hydraThreads: Int = 4,
    val defaultPortRange: String = "",
    val socketTimeoutSec: Int = 5,
    val dnsServer: String = "",
    val customNmapArgs: String = "",
    val bundleWifiOnly: Boolean = true,
    val reinstallingTools: Boolean = false,
    val toolsMessage: String? = null,
)

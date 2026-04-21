package org.csploit.strix.domain.model

data class NetworkInfo(
    val ssid: String,
    val bssid: String?,
    val localIp: String,
    val gatewayIp: String,
    val netmask: String,
    val prefixLength: Int,
    val interfaceName: String,
)

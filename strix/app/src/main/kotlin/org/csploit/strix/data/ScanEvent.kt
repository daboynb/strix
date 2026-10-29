package org.csploit.strix.data

sealed class ScanEvent {
    data class HostFound(val mac: String, val ip: String, val name: String?) : ScanEvent()
    data class HostLost(val ip: String) : ScanEvent()
    data class ScanError(val message: String) : ScanEvent()
    data object ScanEnded : ScanEvent()
}

package org.csploit.strix.ui.packetcapture

import org.csploit.strix.data.PacketCaptureSession

data class PacketCaptureUiState(
    val isRunning: Boolean = false,
    val filter: String = "",
    val verbose: Boolean = false,
    val iface: String = "",
    val packetCount: Int = 0,
    val logLines: List<String> = emptyList(),
)

/** UI-controlled knobs (filter/verbose) live here; session data comes from the runner. */
internal data class LocalState(val filter: String, val verbose: Boolean)

internal fun PacketCaptureSession?.toUiState(local: LocalState, fallbackIface: String): PacketCaptureUiState =
    PacketCaptureUiState(
        isRunning = this?.isRunning ?: false,
        filter = local.filter,
        verbose = local.verbose,
        iface = this?.iface?.takeIf { it.isNotEmpty() } ?: fallbackIface,
        packetCount = this?.packetCount ?: 0,
        logLines = this?.logLines ?: emptyList(),
    )

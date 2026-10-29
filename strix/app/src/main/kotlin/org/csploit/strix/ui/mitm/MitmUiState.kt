package org.csploit.strix.ui.mitm

import org.csploit.strix.data.DnsEntry
import org.csploit.strix.data.MitmCapturedCredential
import org.csploit.strix.data.MitmMode
import org.csploit.strix.data.MitmSession

typealias CapturedCredential = MitmCapturedCredential

data class MitmUiState(
    val isRunning: Boolean = false,
    val mode: MitmMode = MitmMode.SNIFFER,
    val gateway: String = "",
    val iface: String = "",
    val dnsEntries: List<DnsEntry> = listOf(DnsEntry("", "")),
    val credentials: List<CapturedCredential> = emptyList(),
    val logLines: List<String> = emptyList(),
    val error: String? = null,
    val killActive: Boolean = false,
)

internal data class LocalState(
    val mode: MitmMode,
    val gateway: String,
    val iface: String,
    val dnsEntries: List<DnsEntry>,
    val localError: String? = null,
)

internal fun MitmSession?.toUiState(local: LocalState): MitmUiState = MitmUiState(
    isRunning = this?.isRunning ?: false,
    mode = this?.mode ?: local.mode,
    gateway = local.gateway,
    iface = local.iface,
    dnsEntries = local.dnsEntries,
    credentials = this?.credentials ?: emptyList(),
    logLines = this?.logLines ?: emptyList(),
    error = this?.error ?: local.localError,
    killActive = this?.killActive ?: false,
)

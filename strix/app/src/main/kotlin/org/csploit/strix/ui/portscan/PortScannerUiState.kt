package org.csploit.strix.ui.portscan

import org.csploit.strix.data.HttpFingerprintResult
import org.csploit.strix.data.PortScanSession
import org.csploit.strix.domain.model.DefaultCreds
import org.csploit.strix.domain.model.PortInfo

data class PortScannerUiState(
    val isScanning: Boolean = false,
    val isTesting: Boolean = false,
    val ports: List<PortInfo> = emptyList(),
    val os: String? = null,
    val progress: String? = null,
    val error: String? = null,
    val fingerprint: HttpFingerprintResult? = null,
    val credsResult: DefaultCreds? = null,
    val credsTested: Boolean = false,
    val hydraStatus: String? = null,
)
/** State owned by the VM (not by the singleton runner). The credential test is
 *  a side-operation that runs in [viewModelScope] and does not survive navigation;
 *  the fingerprint is stored in the [PortScanSession] by the scan task. */
internal data class LocalUiState(
    val isTesting: Boolean = false,
    val inputError: String? = null,
    val credsResult: DefaultCreds? = null,
    val credsTested: Boolean = false,
    val hydraStatus: String? = null,
    val scanCompleteHandled: Boolean = false,
)

/** Merge the runner's [session] with the VM-owned [local] state. */
internal fun toUiState(session: PortScanSession?, local: LocalUiState): PortScannerUiState =
    PortScannerUiState(
        isScanning = session?.isScanning ?: false,
        isTesting = local.isTesting,
        ports = session?.ports ?: emptyList(),
        os = session?.os,
        progress = session?.progress,
        error = local.inputError ?: session?.error,
        fingerprint = session?.fingerprint,
        credsResult = local.credsResult,
        credsTested = local.credsTested,
        hydraStatus = local.hydraStatus,
    )

package org.csploit.strix.ui.packetcapture

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import org.csploit.strix.core.ScanRegistry
import org.csploit.strix.data.NetworkManager
import org.csploit.strix.data.PacketCaptureRunner
import org.csploit.strix.data.PacketCaptureSession
import org.csploit.strix.ui.navigation.Routes
import javax.inject.Inject

data class PacketCaptureUiState(
    val isRunning: Boolean = false,
    val filter: String = "",
    val verbose: Boolean = false,
    val iface: String = "",
    val packetCount: Int = 0,
    val logLines: List<String> = emptyList(),
)

/** UI-controlled knobs (filter/verbose) live here; session data comes from the runner. */
private data class LocalState(val filter: String, val verbose: Boolean)

@HiltViewModel
class PacketCaptureViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val captureRunner: PacketCaptureRunner,
    private val scanRegistry: ScanRegistry,
    networkManager: NetworkManager,
) : ViewModel() {

    val ip: String = savedStateHandle.get<String>("ip")?.takeIf { it.isNotEmpty() } ?: ""

    private val tag: String = if (ip.isNotEmpty()) "pcap:$ip" else "pcap"
    private val defaultIface = networkManager.detectNetwork()?.interfaceName ?: "wlan0"

    private val _local = MutableStateFlow(
        LocalState(
            filter = if (ip.isNotEmpty()) "host $ip" else "",
            verbose = false,
        ),
    )

    val uiState: StateFlow<PacketCaptureUiState> = combine(
        captureRunner.sessions.map { it[tag] },
        _local,
    ) { session, local ->
        session.toUiState(local, defaultIface)
    }.stateIn(viewModelScope, SharingStarted.Eagerly, PacketCaptureUiState(
        filter = _local.value.filter,
        iface = defaultIface,
    ))

    private var captureJob: Job? = null

    fun setFilter(filter: String) {
        _local.value = _local.value.copy(filter = filter)
    }

    fun setVerbose(verbose: Boolean) {
        _local.value = _local.value.copy(verbose = verbose)
    }

    fun start() {
        captureJob?.cancel()
        captureRunner.clear(tag)
        val local = _local.value
        val label = if (ip.isNotEmpty()) "Packet capture $ip" else "Packet capture"
        captureJob = scanRegistry.launch(
            id = tag,
            label = label,
            deepLink = if (ip.isNotEmpty()) Routes.deepLinkPacketCapture(ip) else null,
        ) {
            captureRunner.capture(tag, filter = local.filter, verbose = local.verbose)
            // Normal exit (tcpdump exited on its own — rare; usually stopped by user/cancel)
            val packets = captureRunner.sessionOf(tag)?.packetCount ?: 0
            scanRegistry.notifications.notifyScanComplete(
                title = "Packet capture stopped",
                message = "$label — $packets packets",
                deepLink = if (ip.isNotEmpty()) Routes.deepLinkPacketCapture(ip) else null,
            )
        }
    }

    fun stop() {
        scanRegistry.cancel(tag)
        captureRunner.appendLog(tag, "[stopped by user]")
        captureJob = null
    }

    override fun onCleared() {
        super.onCleared()
        // captureJob lives in ScanRegistry.appScope and intentionally survives VM destruction.
    }

    private fun PacketCaptureSession?.toUiState(local: LocalState, fallbackIface: String): PacketCaptureUiState =
        PacketCaptureUiState(
            isRunning = this?.isRunning ?: false,
            filter = local.filter,
            verbose = local.verbose,
            iface = this?.iface?.takeIf { it.isNotEmpty() } ?: fallbackIface,
            packetCount = this?.packetCount ?: 0,
            logLines = this?.logLines ?: emptyList(),
        )
}

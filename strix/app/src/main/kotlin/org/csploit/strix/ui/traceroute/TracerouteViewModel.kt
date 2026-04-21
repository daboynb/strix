package org.csploit.strix.ui.traceroute

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import org.csploit.strix.core.Logger
import org.csploit.strix.core.ScanRegistry
import org.csploit.strix.data.TracerouteRunner
import org.csploit.strix.data.TracerouteSession
import org.csploit.strix.domain.model.TracerouteHop
import org.csploit.strix.ui.navigation.Routes
import javax.inject.Inject

data class TracerouteUiState(
    val isTracing: Boolean = false,
    val hops: List<TracerouteHop> = emptyList(),
    val error: String? = null,
)

@HiltViewModel
class TracerouteViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val tracerouteRunner: TracerouteRunner,
    private val scanRegistry: ScanRegistry,
) : ViewModel() {

    val ip: String = savedStateHandle["ip"] ?: ""

    val uiState: StateFlow<TracerouteUiState> = tracerouteRunner.sessions
        .map { it[ip].toUiState() }
        .stateIn(viewModelScope, SharingStarted.Eagerly, TracerouteUiState())

    private var traceJob: Job? = null

    fun startTrace() {
        traceJob?.cancel()
        tracerouteRunner.clear(ip)
        traceJob = scanRegistry.launch(
            id = "traceroute:$ip",
            label = "Traceroute $ip",
            deepLink = Routes.deepLinkTraceroute(ip),
        ) {
            tracerouteRunner.trace(ip)
            val hopCount = tracerouteRunner.sessionOf(ip)?.hops?.size ?: 0
            Logger.info("Traceroute: complete for $ip, $hopCount hops")
            scanRegistry.notifications.notifyScanComplete(
                title = "Traceroute complete",
                message = "$ip — $hopCount hops",
                deepLink = Routes.deepLinkTraceroute(ip),
            )
        }
    }

    fun stopTrace() {
        scanRegistry.cancel("traceroute:$ip")
        traceJob = null
    }

    override fun onCleared() {
        super.onCleared()
        // traceJob lives in ScanRegistry.appScope and intentionally survives VM destruction.
    }

    private fun TracerouteSession?.toUiState(): TracerouteUiState = TracerouteUiState(
        isTracing = this?.isTracing ?: false,
        hops = this?.hops ?: emptyList(),
        error = this?.error,
    )
}

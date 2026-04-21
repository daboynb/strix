package org.csploit.strix.ui.portscan

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
import kotlinx.coroutines.launch
import org.csploit.strix.core.Logger
import org.csploit.strix.core.ScanRegistry
import org.csploit.strix.data.HttpFingerprintResult
import org.csploit.strix.data.PortScanSession
import org.csploit.strix.data.PortScanner
import org.csploit.strix.data.RouterAnalyzer
import org.csploit.strix.domain.model.DefaultCreds
import org.csploit.strix.domain.model.PortInfo
import org.csploit.strix.ui.navigation.Routes
import javax.inject.Inject

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

/** State owned by the VM (not by the singleton runner). Fingerprint/creds are
 *  side-operations that run in [viewModelScope] and do not survive navigation. */
private data class LocalUiState(
    val isTesting: Boolean = false,
    val fingerprint: HttpFingerprintResult? = null,
    val credsResult: DefaultCreds? = null,
    val credsTested: Boolean = false,
    val hydraStatus: String? = null,
    val scanCompleteHandled: Boolean = false,
)

@HiltViewModel
class PortScannerViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val portScanner: PortScanner,
    private val routerAnalyzer: RouterAnalyzer,
    private val scanRegistry: ScanRegistry,
) : ViewModel() {

    val ip: String = savedStateHandle["ip"] ?: ""

    var portRange: String = ""
        private set

    private val _localState = MutableStateFlow(LocalUiState())

    val uiState: StateFlow<PortScannerUiState> = combine(
        portScanner.sessions.map { it[ip] },
        _localState,
    ) { session, local ->
        PortScannerUiState(
            isScanning = session?.isScanning ?: false,
            isTesting = local.isTesting,
            ports = session?.ports ?: emptyList(),
            os = session?.os,
            progress = session?.progress,
            error = session?.error,
            fingerprint = local.fingerprint,
            credsResult = local.credsResult,
            credsTested = local.credsTested,
            hydraStatus = local.hydraStatus,
        )
    }.stateIn(viewModelScope, SharingStarted.Eagerly, PortScannerUiState())

    private var scanJob: Job? = null
    private var credJob: Job? = null

    fun setPortRange(range: String) {
        portRange = range
    }

    fun startScan() {
        scanJob?.cancel()
        _localState.value = LocalUiState()  // reset fingerprint/creds for the new run
        portScanner.clear(ip)
        Logger.info("PortScannerVM: startScan ip=$ip range='${portRange.ifBlank { "default" }}'")

        scanJob = scanRegistry.launch(
            id = "portscan:$ip",
            label = "Port scan $ip",
            deepLink = Routes.deepLinkPortScanner(ip),
        ) {
            portScanner.scan(ip, portRange.ifBlank { null })
            // Natural completion: nmap exited on its own. Cancelled runs throw
            // CancellationException and never reach here.
            val session = portScanner.sessionOf(ip)
            val portCount = session?.ports?.size ?: 0
            scanRegistry.notifications.notifyScanComplete(
                title = "Port scan complete",
                message = "$ip — $portCount open ports",
                deepLink = Routes.deepLinkPortScanner(ip),
            )
            val httpPorts = session?.ports.orEmpty()
                .filter { it.state == "open" }
                .filter { p ->
                    p.service?.contains("http", ignoreCase = true) == true ||
                        p.service?.contains("ssl", ignoreCase = true) == true
                }
                .map { it.number }
            if (httpPorts.isNotEmpty()) fingerprint(httpPorts)
        }
    }

    fun stopScan() {
        scanRegistry.cancel("portscan:$ip")
        scanJob = null
        credJob?.cancel()
        credJob = null
        _localState.value = _localState.value.copy(isTesting = false)
    }

    fun testCredentials() {
        val fp = _localState.value.fingerprint ?: return
        val adminUrl = fp.adminUrl ?: return

        credJob?.cancel()
        _localState.value = _localState.value.copy(
            isTesting = true,
            credsResult = null,
            credsTested = false,
            hydraStatus = null,
        )

        credJob = viewModelScope.launch {
            val creds = routerAnalyzer.credentialTester.test(ip, adminUrl, fp.wwwAuthenticate) { status ->
                _localState.value = _localState.value.copy(hydraStatus = status)
            }
            _localState.value = _localState.value.copy(
                isTesting = false,
                credsResult = creds,
                credsTested = true,
            )
        }
    }

    fun stopCredentialTest() {
        credJob?.cancel()
        credJob = null
        _localState.value = _localState.value.copy(isTesting = false)
    }

    private fun fingerprint(ports: List<Int>) {
        // Runs in the registry's appScope block (outer scanJob coroutine) so it
        // survives VM destruction alongside the scan completion.
        viewModelScope.launch {
            val result = routerAnalyzer.httpProbe.fingerprint(ip, ports)
            _localState.value = _localState.value.copy(fingerprint = result)
        }
    }

    override fun onCleared() {
        super.onCleared()
        Logger.info("PortScannerVM: onCleared ip=$ip scanActive=${scanRegistry.isActive("portscan:$ip")}")
        // scanJob runs in ScanRegistry.appScope and intentionally survives VM destruction.
        credJob?.cancel()
    }
}

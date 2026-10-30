package org.csploit.strix.ui.hostlist

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import org.csploit.strix.core.Logger
import org.csploit.strix.core.ScanRegistry
import org.csploit.strix.data.bundle.BundleUpdateManager
import org.csploit.strix.data.NetworkManager
import org.csploit.strix.ui.navigation.Routes
import org.csploit.strix.data.NetworkScanner
import org.csploit.strix.data.ScanEvent
import org.csploit.strix.data.TargetRepository
import org.csploit.strix.domain.model.Host
import org.csploit.strix.domain.model.NetworkInfo
import java.net.InetAddress
import javax.inject.Inject

@HiltViewModel
class HostListViewModel @Inject constructor(
    private val networkScanner: NetworkScanner,
    private val networkManager: NetworkManager,
    private val targetRepository: TargetRepository,
    private val scanRegistry: ScanRegistry,
    bundleUpdates: BundleUpdateManager,
) : ViewModel() {

    /** e.g. "Metasploit 6.4.130-r1" when a newer bundle than the installed one is published, else null. */
    val bundleUpdateBanner: StateFlow<String?> =
        combine(bundleUpdates.tools.state, bundleUpdates.msf.state) { t, m ->
            listOfNotNull(t, m)
                .filter { it.availableVersion != null && it.installedVersion != null }
                .joinToString(" / ") { "${it.label} ${it.availableVersion}" }
                .ifEmpty { null }
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), null)

    val hosts: StateFlow<List<Host>> = targetRepository.hosts
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    private val _networkInfo = MutableStateFlow<NetworkInfo?>(null)
    val networkInfo: StateFlow<NetworkInfo?> = _networkInfo.asStateFlow()

    // Derived from the registry so a recreated VM sees a scan started by a
    // previous instance, and the flag drops however the task ends.
    val isScanning: StateFlow<Boolean> = scanRegistry.activeTasks
        .map { tasks -> tasks.any { it.id == SCAN_ID } }
        .stateIn(viewModelScope, SharingStarted.Eagerly, scanRegistry.activeTasks.value.any { it.id == SCAN_ID })

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()

    init {
        // Detect network on startup but don't start scanning
        _networkInfo.value = networkManager.detectNetwork()
    }

    fun startScan() {
        targetRepository.clear()

        val info = networkManager.detectNetwork()
        if (info == null) {
            _error.value = "Not connected to WiFi"
            return
        }
        _networkInfo.value = info
        _error.value = null

        scanRegistry.launch(
            id = SCAN_ID,
            label = "Network discovery",
            deepLink = Routes.deepLinkHostList(),
            onError = { t ->
                Logger.error("Scan failed: ${t.javaClass.simpleName}: ${t.message}")
                _error.value = "Scan failed: ${t.message ?: t.javaClass.simpleName}"
            },
        ) {
            // Per-run state and helper coroutines belong to the task (this
            // scope), not to the VM: they keep working if the VM is recreated
            // and are cancelled together with the scan.
            val resolvedIps = mutableSetOf<String>()
            val pendingDisconnects = mutableMapOf<String, Job>()
            networkScanner.scan("${info.gatewayIp}/${info.prefixLength}", info.interfaceName).collect { event ->
                when (event) {
                    is ScanEvent.HostFound -> {
                        pendingDisconnects.remove(event.ip)?.cancel()
                        targetRepository.addOrUpdate(event.ip, event.mac, event.name)
                        if (event.name.isNullOrBlank() && event.ip !in resolvedIps) {
                            resolvedIps.add(event.ip)
                            launch(Dispatchers.IO) { resolveHostname(event.ip) }
                        }
                    }
                    is ScanEvent.HostLost -> {
                        pendingDisconnects[event.ip]?.cancel()
                        pendingDisconnects[event.ip] = launch {
                            delay(5000)
                            targetRepository.markDisconnected(event.ip)
                            pendingDisconnects.remove(event.ip)
                        }
                    }
                    is ScanEvent.ScanError -> {
                        Logger.error("Scan error: ${event.message}")
                        _error.value = event.message
                    }
                    is ScanEvent.ScanEnded -> {
                        val hostCount = targetRepository.hosts.value.size
                        scanRegistry.notifications.notifyScanComplete(
                            title = "Network discovery complete",
                            message = "$hostCount hosts on ${info.gatewayIp}/${info.prefixLength}",
                            deepLink = Routes.deepLinkHostList(),
                        )
                    }
                }
            }
        }
    }

    fun addManualHost(input: String, name: String?) {
        val trimmed = input.trim()
        if (trimmed.isEmpty()) return
        // If the input looks like an IPv4, store it directly.
        if (IPV4_REGEX.matches(trimmed)) {
            targetRepository.addManual(trimmed, name)
            return
        }
        // Otherwise treat it as a hostname: resolve to an IP so downstream
        // tools (nmap, etc.) don't need /etc/resolv.conf at run time.
        // Temporarily store the hostname as the id; once resolved we upsert
        // the entry under the real IP and drop the hostname-keyed one.
        targetRepository.addManual(trimmed, name ?: trimmed)
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val addr = InetAddress.getByName(trimmed)
                val resolvedIp = addr.hostAddress ?: return@launch
                if (resolvedIp != trimmed) {
                    targetRepository.remove(trimmed)
                    targetRepository.addManual(resolvedIp, name ?: trimmed)
                }
            } catch (_: Exception) {}
        }
    }

    companion object {
        private const val SCAN_ID = "netscan"
        private val IPV4_REGEX = Regex("""^(?:\d{1,3}\.){3}\d{1,3}$""")
    }

    fun stopScan() {
        scanRegistry.cancel(SCAN_ID)
    }

    private fun resolveHostname(ip: String) {
        try {
            val addr = InetAddress.getByName(ip)
            val hostname = addr.canonicalHostName
            if (hostname != null && hostname != ip) {
                targetRepository.updateName(ip, hostname)
            }
        } catch (_: Exception) {}
    }

    override fun onCleared() {
        super.onCleared()
        // The scan lives in ScanRegistry.appScope and intentionally survives VM destruction.
    }
}

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
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import org.csploit.strix.core.Logger
import org.csploit.strix.core.ScanRegistry
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
) : ViewModel() {

    val hosts: StateFlow<List<Host>> = targetRepository.hosts
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    private val _networkInfo = MutableStateFlow<NetworkInfo?>(null)
    val networkInfo: StateFlow<NetworkInfo?> = _networkInfo.asStateFlow()

    private val _isScanning = MutableStateFlow(false)
    val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()

    private var scanJob: Job? = null
    private val resolvedIps = mutableSetOf<String>()
    private val pendingDisconnects = mutableMapOf<String, Job>()

    init {
        // Detect network on startup but don't start scanning
        _networkInfo.value = networkManager.detectNetwork()
        if (scanRegistry.isActive("netscan")) {
            _isScanning.value = true
        }
    }

    fun startScan() {
        scanJob?.cancel()
        targetRepository.clear()
        resolvedIps.clear()
        pendingDisconnects.values.forEach { it.cancel() }
        pendingDisconnects.clear()

        val info = networkManager.detectNetwork()
        if (info == null) {
            _error.value = "Not connected to WiFi"
            return
        }
        _networkInfo.value = info
        _error.value = null
        _isScanning.value = true

        scanJob = scanRegistry.launch(
            id = "netscan",
            label = "Network discovery",
            deepLink = Routes.deepLinkHostList(),
        ) {
            networkScanner.scan("${info.gatewayIp}/${info.prefixLength}").collect { event ->
                when (event) {
                    is ScanEvent.HostFound -> {
                        pendingDisconnects.remove(event.ip)?.cancel()
                        targetRepository.addOrUpdate(event.ip, event.mac, event.name)
                        if (event.name.isNullOrBlank() && event.ip !in resolvedIps) {
                            resolvedIps.add(event.ip)
                            resolveHostname(event.ip)
                        }
                    }
                    is ScanEvent.HostLost -> {
                        pendingDisconnects[event.ip]?.cancel()
                        pendingDisconnects[event.ip] = viewModelScope.launch {
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
                        _isScanning.value = false
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
            targetRepository.addOrUpdate(trimmed, "manual", name)
            return
        }
        // Otherwise treat it as a hostname: resolve to an IP so downstream
        // tools (nmap, etc.) don't need /etc/resolv.conf at run time.
        // Temporarily store the hostname as the id; once resolved we upsert
        // the entry under the real IP and drop the hostname-keyed one.
        targetRepository.addOrUpdate(trimmed, "manual", name ?: trimmed)
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val addr = InetAddress.getByName(trimmed)
                val resolvedIp = addr.hostAddress ?: return@launch
                if (resolvedIp != trimmed) {
                    targetRepository.remove(trimmed)
                    targetRepository.addOrUpdate(resolvedIp, "manual", name ?: trimmed)
                }
            } catch (_: Exception) {}
        }
    }

    companion object {
        private val IPV4_REGEX = Regex("""^(?:\d{1,3}\.){3}\d{1,3}$""")
    }

    fun stopScan() {
        scanRegistry.cancel("netscan")
        scanJob = null
        pendingDisconnects.values.forEach { it.cancel() }
        pendingDisconnects.clear()
        _isScanning.value = false
    }

    private fun resolveHostname(ip: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val addr = InetAddress.getByName(ip)
                val hostname = addr.canonicalHostName
                if (hostname != null && hostname != ip) {
                    targetRepository.updateName(ip, hostname)
                }
            } catch (_: Exception) {}
        }
    }

    override fun onCleared() {
        super.onCleared()
        // scanJob lives in ScanRegistry.appScope and intentionally survives VM destruction.
    }
}

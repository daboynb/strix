package org.csploit.strix.ui.mitm

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import org.csploit.strix.core.ScanRegistry
import org.csploit.strix.data.DnsEntry
import org.csploit.strix.data.DnsSpoofServer
import org.csploit.strix.data.MitmCapturedCredential
import org.csploit.strix.data.MitmMode
import org.csploit.strix.data.MitmRunner
import org.csploit.strix.data.MitmSessionStore
import org.csploit.strix.data.NetworkManager
import org.csploit.strix.ui.navigation.Routes
import javax.inject.Inject

@HiltViewModel
class MitmViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val mitmRunner: MitmRunner,
    private val networkManager: NetworkManager,
    private val dnsSpoofServer: DnsSpoofServer,
    private val scanRegistry: ScanRegistry,
    private val store: MitmSessionStore,
) : ViewModel() {

    val ip: String = savedStateHandle["ip"] ?: ""
    val mac: String? = savedStateHandle.get<String>("mac")?.takeIf { it.isNotEmpty() }
    private val initialMode: MitmMode =
        runCatching { MitmMode.valueOf(savedStateHandle.get<String>("mode") ?: "") }
            .getOrDefault(MitmMode.SNIFFER)

    private val _local: MutableStateFlow<LocalState>
    private val trafficParser = MitmTrafficParser(
        ip = ip,
        log = { store.appendLog(ip, it) },
        onCredential = ::addCredential,
    )

    // All MITM coroutines run in ScanRegistry.appScope so setup, teardown and
    // cleanup outlive the ViewModel (Stop then immediate back must not cut
    // iptables/ip_forward restoration). The arpspoof/sniffer tasks are owned by
    // ScanRegistry (cancelled by id); setup/kill jobs are tracked here.
    private var setupJob: Job? = null
    private var killJob: Job? = null

    // Set while a teardown is in flight so the process collectors don't mistake
    // our own cancellation for an unexpected exit and trigger a second teardown.
    @Volatile
    private var tearingDown = false

    init {
        val net = networkManager.detectNetwork()
        _local = MutableStateFlow(
            LocalState(
                mode = initialMode,
                gateway = net?.gatewayIp ?: "",
                iface = net?.interfaceName ?: "",
                dnsEntries = listOf(DnsEntry("", "")),
            ),
        )

        // MITM modes are mutually exclusive per host — one session, one shared
        // arpspoof job. Opening this screen for a mode different from whatever
        // is stored for [ip] must tear down the previous mode (and drop its
        // stale session) so its notification/state doesn't leak into this one.
        val existing = store.sessionOf(ip)
        if (existing != null && existing.mode != initialMode) {
            if (existing.isRunning) {
                teardownMode(existing.mode, existing.killActive)
            }
            store.clear(ip)
        }
    }

    val uiState: StateFlow<MitmUiState> = combine(
        store.sessions.map { it[ip] },
        _local,
    ) { session, local ->
        session.toUiState(local)
    }.stateIn(
        viewModelScope,
        SharingStarted.Eagerly,
        null.toUiState(_local.value),
    )

    fun updateDnsEntry(index: Int, entry: DnsEntry) {
        val entries = _local.value.dnsEntries.toMutableList()
        if (index in entries.indices) {
            entries[index] = entry
            _local.value = _local.value.copy(dnsEntries = entries)
        }
    }

    fun addDnsEntry() {
        _local.value = _local.value.copy(dnsEntries = _local.value.dnsEntries + DnsEntry("", ""))
    }

    fun removeDnsEntry(index: Int) {
        val entries = _local.value.dnsEntries.toMutableList()
        if (index in entries.indices && entries.size > 1) {
            entries.removeAt(index)
            _local.value = _local.value.copy(dnsEntries = entries)
        }
    }

    fun start() {
        val local = _local.value
        if (local.gateway.isEmpty()) {
            _local.value = local.copy(localError = "No gateway detected")
            return
        }

        val validDns = local.dnsEntries.filter {
            it.hostname.isNotBlank() && it.address.isNotBlank()
        }
        if (local.mode == MitmMode.DNS_SPOOF && validDns.isEmpty()) {
            _local.value = local.copy(localError = "Add at least one DNS entry")
            return
        }

        stopAll()
        store.resetForNewRun(ip, local.mode)
        _local.value = local.copy(localError = null)
        tearingDown = false
        val mode = local.mode
        // Stop-then-immediately-Start: the previous run's cleanup must finish
        // before our setup, or it would revert the rules we are about to apply.
        val pendingTeardown = store.teardownOf(ip)

        // Setup runs in appScope and is tracked as setupJob so Stop can cancel
        // it mid-sequence — before this fix the ~8 su setup commands (and then
        // arpspoof/tcpdump) kept running after Stop. On cancel/failure we revert
        // whatever setup already applied.
        setupJob = scanRegistry.appScope.launch {
            try {
                pendingTeardown?.join()
                mitmRunner.setup(mode) { store.appendLog(ip, it) }
                store.appendLog(ip, "[+] Setup complete — starting MITM")
                startMitmProcesses(mode, validDns)
            } catch (ce: CancellationException) {
                // Stop landed during setup: teardownMode() will run cleanup.
                throw ce
            } catch (e: Exception) {
                store.appendLog(ip, "[!] Setup error: ${e.message}")
                store.setRunning(ip, mode, false)
                teardownMode(mode, wasKilled = false)
            }
        }
    }

    private fun startMitmProcesses(mode: MitmMode, validDns: List<DnsEntry>) {
        // arpspoof for both modes: ettercap's own ARP poisoner (-M arp) is
        // broken on Android, so we always rely on the external arpspoof to
        // route the victim's traffic through us, and let ettercap run as a
        // passive sniffer + dns_spoof plugin.
        scanRegistry.launch(
            id = "mitm-arp:$ip",
            label = "ARP spoof $ip",
            deepLink = Routes.deepLinkMitm(ip, mac ?: "", mode.name),
        ) {
            try {
                store.appendLog(ip, "[+] ARP poisoning active")
                mitmRunner.startArpSpoof(ip).collect { event ->
                    handleArpSpoofEvent(event, { store.appendLog(ip, it) }) {
                        onProcessDied(mode, "arpspoof")
                    }
                }
            } catch (ce: CancellationException) {
                throw ce
            } catch (_: Exception) {}
        }

        when (mode) {
            MitmMode.SNIFFER -> {
                scanRegistry.launch(
                    id = "mitm-sniff:$ip",
                    label = "Credential sniffer $ip",
                    deepLink = Routes.deepLinkMitm(ip, mac ?: "", mode.name),
                ) {
                    try {
                        store.appendLog(ip, "[+] Starting credential sniffer (tcpdump)...")
                        mitmRunner.startCredentialSniffer(ip).collect { event ->
                            handleSnifferEvent(
                                event,
                                log = { store.appendLog(ip, it) },
                                onTraffic = trafficParser::parse,
                            ) { onProcessDied(mode, "sniffer") }
                        }
                    } catch (ce: CancellationException) {
                        throw ce
                    } catch (e: Exception) {
                        store.appendLog(ip, "[sniffer error: ${e.message}]")
                    }
                }
            }
            MitmMode.DNS_SPOOF -> {
                val upstream = networkManager.detectNetwork()?.gatewayIp ?: "8.8.8.8"
                dnsSpoofServer.start(validDns, upstream) { line -> store.appendLog(ip, line) }
            }
            MitmMode.KILL -> {
                // arpspoof routes victim's traffic through us; the kill rules
                // drop/RST every forwarded packet so the victim loses
                // connectivity until we stop. Tracked as killJob and run in
                // appScope so Stop can cancel it — and so teardown can wait for
                // it before removing the rules (otherwise a Stop that lands
                // mid-apply would leave rules in place, victim offline forever).
                killJob = scanRegistry.appScope.launch {
                    mitmRunner.applyKillRules(ip) { store.appendLog(ip, it) }
                    store.setKillActive(ip, true)
                    store.appendLog(ip, "[!] connection killed")
                }
            }
        }
    }

    /**
     * A MITM subprocess terminated on its own (not via our Stop). Reflect the
     * real state and tear the rest down + clean up, unless a teardown is
     * already running (in which case this death is our own doing).
     */
    private fun onProcessDied(mode: MitmMode, which: String) {
        if (tearingDown) return
        if (store.sessionOf(ip)?.isRunning != true) return
        store.appendLog(ip, "[!] $which stopped — ending MITM")
        val wasKilled = store.sessionOf(ip)?.killActive ?: false
        store.setRunning(ip, mode, false)
        store.setKillActive(ip, false)
        teardownMode(mode, wasKilled)
    }

    fun stop() {
        val session = store.sessionOf(ip)
        val mode = session?.mode ?: _local.value.mode
        val wasKilled = session?.killActive ?: false
        store.appendLog(ip, "[stopped by user]")
        store.setRunning(ip, mode, false)
        store.setKillActive(ip, false)
        teardownMode(mode, wasKilled)
    }

    /**
     * Cancel every process for [mode] and undo its system-level changes (kill
     * rules, ettercap/iptables cleanup). Shared by [stop] and the mode-switch
     * reconciliation in `init` — opening a different MITM mode for a host must
     * first tear down whatever mode was previously running, since all modes
     * share the single per-host arpspoof job + session.
     */
    private fun teardownMode(mode: MitmMode, wasKilled: Boolean) {
        tearingDown = true
        val pending = stopAll()
        // Cleanup runs in appScope (not viewModelScope) so Stop-then-back can't
        // cancel it half-way; MitmRunner.cleanup/removeKillRules are themselves
        // NonCancellable. We join the cancelled setup/kill jobs first so their
        // partial su commands have stopped before we revert them.
        val previousTeardown = store.teardownOf(ip)
        val job = scanRegistry.appScope.launch {
            previousTeardown?.join()
            pending.forEach { runCatching { it.join() } }
            if (wasKilled) mitmRunner.removeKillRules(ip)
            mitmRunner.cleanup(mode)
            tearingDown = false
        }
        store.setTeardown(ip, job)
    }

    /** Cancel every running MITM coroutine. Returns the local jobs to join. */
    private fun stopAll(): List<Job> {
        scanRegistry.cancel("mitm-arp:$ip")
        scanRegistry.cancel("mitm-sniff:$ip")
        dnsSpoofServer.stop()
        val jobs = listOfNotNull(setupJob, killJob)
        setupJob?.cancel()
        setupJob = null
        killJob?.cancel()
        killJob = null
        return jobs
    }

    fun clearError() {
        _local.value = _local.value.copy(localError = null)
        store.setError(ip, null)
    }

    private fun addCredential(protocol: String, endpoint: String, user: String, pass: String) {
        val added = store.addCredential(ip, MitmCapturedCredential(protocol, endpoint, user, pass))
        if (added) {
            scanRegistry.notifications.notifyCredentialCaptured(
                host = "$protocol $endpoint",
                credential = "$user:$pass",
                deepLink = Routes.deepLinkMitm(ip, mac ?: "", _local.value.mode.name),
            )
        }
    }

    override fun onCleared() {
        super.onCleared()
        // The arpspoof/sniffer tasks live in ScanRegistry.appScope and survive VM destruction
        // so the attack continues while the user navigates around. DnsSpoofServer already
        // uses its own singleton scope. Call stop() explicitly from the UI to end.
    }

}

package org.csploit.strix.ui.mitm

import android.util.Base64
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
import org.csploit.strix.core.ProcessEvent
import org.csploit.strix.core.ScanRegistry
import org.csploit.strix.data.DnsEntry
import org.csploit.strix.data.DnsSpoofServer
import org.csploit.strix.data.MitmCapturedCredential
import org.csploit.strix.data.MitmMode
import org.csploit.strix.data.MitmRunner
import org.csploit.strix.data.MitmSession
import org.csploit.strix.data.MitmSessionStore
import org.csploit.strix.data.NetworkManager
import org.csploit.strix.ui.navigation.Routes
import javax.inject.Inject

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

private data class LocalState(
    val mode: MitmMode,
    val gateway: String,
    val iface: String,
    val dnsEntries: List<DnsEntry>,
    val localError: String? = null,
)

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
    private var lastFtpUser: String? = null

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
                    when (event) {
                        is ProcessEvent.StdoutLine -> {} // suppress arp reply noise
                        is ProcessEvent.StderrLine -> {
                            if (event.line.contains("couldn't") || event.line.contains("error"))
                                store.appendLog(ip, "[arpspoof] ${event.line}")
                        }
                        is ProcessEvent.Exited -> {
                            store.appendLog(ip, "[arpspoof exited: ${event.code}]")
                            onProcessDied(mode, "arpspoof")
                        }
                        is ProcessEvent.Killed -> store.appendLog(ip, "[arpspoof stopped]")
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
                            when (event) {
                                is ProcessEvent.StdoutLine -> {
                                    parseTrafficLine(event.line)
                                    val trimmed = event.line.trim()
                                    if (trimmed.isNotEmpty() && !trimmed.startsWith("E.")) {
                                        store.appendLog(ip, "[tcp] ${trimmed.take(100)}")
                                    }
                                }
                                is ProcessEvent.StderrLine -> {
                                    if (event.line.contains("listening on") || event.line.contains("packets")) {
                                        store.appendLog(ip, "[sniffer] ${event.line}")
                                    }
                                }
                                is ProcessEvent.Exited -> {
                                    store.appendLog(ip, "[sniffer exited: ${event.code}]")
                                    onProcessDied(mode, "sniffer")
                                }
                                is ProcessEvent.Killed -> store.appendLog(ip, "[sniffer killed]")
                            }
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

    /**
     * Parse tcpdump ASCII output for credentials.
     * HTTP Basic Auth, POST form data, FTP USER/PASS.
     */
    private fun parseTrafficLine(line: String) {
        // HTTP Basic Auth: "Authorization: Basic BASE64"
        MitmRunner.BASIC_AUTH_REGEX.find(line)?.let { match ->
            val decoded = try {
                String(Base64.decode(match.groupValues[1], Base64.DEFAULT))
            } catch (_: Exception) { return@let }
            val parts = decoded.split(":", limit = 2)
            if (parts.size == 2) {
                addCredential("HTTP", "Basic Auth", parts[0], parts[1])
                store.appendLog(ip, "[!] HTTP Basic Auth: ${parts[0]}:${parts[1]}")
            }
            return
        }

        // POST form: "username=X&password=Y"
        MitmRunner.POST_CRED_REGEX.find(line)?.let { match ->
            addCredential("HTTP", "POST", match.groupValues[1], match.groupValues[2])
            store.appendLog(ip, "[!] HTTP POST: ${match.groupValues[1]}:${match.groupValues[2]}")
            return
        }

        // FTP: "USER xxx" / "PASS xxx"
        MitmRunner.FTP_REGEX.find(line)?.let { match ->
            val cmd = match.groupValues[1].uppercase()
            val value = match.groupValues[2].trim()
            if (cmd == "USER") {
                lastFtpUser = value
            } else if (cmd == "PASS" && lastFtpUser != null) {
                addCredential("FTP", ip, lastFtpUser!!, value)
                store.appendLog(ip, "[!] FTP: $lastFtpUser:$value")
                lastFtpUser = null
            }
            return
        }
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

    private fun MitmSession?.toUiState(local: LocalState): MitmUiState = MitmUiState(
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
}

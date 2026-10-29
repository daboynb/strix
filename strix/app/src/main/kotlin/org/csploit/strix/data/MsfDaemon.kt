package org.csploit.strix.data

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.csploit.strix.core.Logger
import org.csploit.strix.core.ProcessEvent
import org.csploit.strix.core.ProcessManager
import org.csploit.strix.core.StrixNotifications
import org.csploit.strix.data.bundle.RootFs
import javax.inject.Inject
import javax.inject.Singleton

enum class DaemonState {
    STOPPED,
    STARTING,
    READY,
    FAILED,
}

@Singleton
class MsfDaemon @Inject constructor(
    private val processManager: ProcessManager,
    private val toolManager: ToolManager,
    private val appSettings: AppSettings,
    private val rpcClient: MsfRpcClient,
    private val notifications: StrixNotifications,
) {
    // Singleton scope — survives beyond any single ViewModel. Startup,
    // readiness polling and teardown all run here so leaving the screen that
    // called start() can't strand the daemon in STARTING.
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val _state = MutableStateFlow(DaemonState.STOPPED)
    val state: StateFlow<DaemonState> = _state.asStateFlow()

    private val _logs = MutableStateFlow<List<String>>(emptyList())
    val logs: StateFlow<List<String>> = _logs.asStateFlow()

    /** Guards [generation], the job references and state transitions. */
    private val lock = Any()

    /**
     * Bumped on every start()/stop(). Callbacks from an older run (its
     * collector receiving Killed/Exited after a restart, a stale readiness
     * poll) compare against it and are ignored.
     */
    private var generation = 0L
    private var startJob: Job? = null
    private var processJob: Job? = null
    private var sessionPollJob: Job? = null

    /** Last lifecycle operation; the next one joins it so pkill never races a fresh daemon. */
    private var lastOp: Job? = null

    /** Set while a bundle swap replaces ruby/ and msf/: start() is refused. */
    private var maintenance = false

    private val rootFs = RootFs()

    val isRunning: Boolean get() = _state.value == DaemonState.READY

    /**
     * Start msfrpcd in foreground mode and wait until it accepts RPC calls.
     * If a start is already in flight, joins it. Returns once the daemon is
     * READY, FAILED or STOPPED. Cancelling the caller only stops the wait —
     * the startup itself keeps running in the daemon's own scope.
     */
    suspend fun start() {
        val job = synchronized(lock) {
            if (maintenance) {
                appendLog("[Metasploit update in progress, start refused]")
                return
            }
            when (_state.value) {
                DaemonState.READY -> null
                DaemonState.STARTING -> startJob
                DaemonState.STOPPED, DaemonState.FAILED -> {
                    val gen = ++generation
                    _state.value = DaemonState.STARTING
                    _logs.value = emptyList()
                    val previous = lastOp
                    scope.launch {
                        previous?.join()
                        runStart(gen)
                    }.also {
                        startJob = it
                        lastOp = it
                    }
                }
            }
        }
        job?.join()
    }

    private suspend fun runStart(gen: Long) {
        // Kill any orphaned msfrpcd processes from previous sessions
        killOrphanedMsfrpcd()
        if (!isCurrent(gen)) return

        if (!toolManager.isMsfInstalled()) {
            appendLog("[Metasploit is not installed: download it from the Metasploit screen]")
            transition(gen) { DaemonState.FAILED }
            return
        }
        migrateMsfHome(toolManager, rootFs)
        val launch = buildMsfrpcdLaunch(toolManager, appSettings)
        val port = launch.port

        // Process watcher lives in the singleton scope, beyond this startup sequence
        val procJob = scope.launch {
            processManager.execute(
                command = launch.command,
                env = launch.env,
                asSu = true,
                secrets = launch.secrets,
            ).collect { event ->
                when (event) {
                    is ProcessEvent.StdoutLine -> appendLog(event.line)
                    is ProcessEvent.StderrLine -> appendLog(event.line)
                    is ProcessEvent.Exited -> {
                        appendLog("[daemon exited with code ${event.code}]")
                        transition(gen) { current ->
                            when {
                                current == DaemonState.STOPPED || current == DaemonState.FAILED -> null
                                event.code == 0 -> DaemonState.STOPPED
                                else -> DaemonState.FAILED
                            }
                        }
                    }
                    is ProcessEvent.Killed -> {
                        appendLog("[daemon killed by signal ${event.signal}]")
                        transition(gen) { current ->
                            when (current) {
                                // Died on its own while starting: that's a failure.
                                DaemonState.STARTING -> DaemonState.FAILED
                                DaemonState.READY -> DaemonState.STOPPED
                                DaemonState.STOPPED, DaemonState.FAILED -> null
                            }
                        }
                    }
                }
            }
        }
        synchronized(lock) {
            if (gen != generation) {
                procJob.cancel()
                return
            }
            processJob = procJob
        }

        // Poll for readiness by attempting RPC connection
        val timeout = 120_000L
        val startTime = System.currentTimeMillis()
        while (isCurrent(gen) && _state.value == DaemonState.STARTING) {
            if (System.currentTimeMillis() - startTime > timeout) {
                appendLog("[timeout: daemon did not become ready within ${timeout / 1000}s]")
                failStartup(gen, procJob)
                return
            }

            // Try connecting via RPC — more reliable than scraping log strings
            try {
                rpcClient.configure(
                    host = appSettings.msfRpcHost,
                    port = appSettings.msfRpcPort,
                    ssl = appSettings.msfRpcSsl,
                )
                rpcClient.login(appSettings.msfRpcUser, appSettings.msfRpcPassword)
                val ready = transition(gen) { current ->
                    if (current == DaemonState.STARTING) DaemonState.READY else null
                }
                if (ready) {
                    Logger.info("MsfDaemon: daemon is ready on port $port")
                    startSessionPolling(gen)
                }
                return
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                // Not ready yet, wait and retry
                delay(2000)
            }
        }
    }

    /** Startup timed out: don't leave msfrpcd running as root behind a FAILED state. */
    private fun failStartup(gen: Long, procJob: Job) {
        val failed = transition(gen) { DaemonState.FAILED }
        if (!failed) return
        procJob.cancel()
        rpcClient.disconnect()
        killOrphanedMsfrpcd()
    }

    fun stop() {
        synchronized(lock) {
            generation++
            startJob?.cancel()
            startJob = null
            sessionPollJob?.cancel()
            sessionPollJob = null
            processJob?.cancel()
            processJob = null
            _state.value = DaemonState.STOPPED
            // pkill blocks (su + waitFor + sleep): never on the caller's (Main) thread.
            val previous = lastOp
            lastOp = scope.launch {
                previous?.join()
                rpcClient.disconnect()
                killOrphanedMsfrpcd()
            }
        }
        appendLog("[daemon stopped]")
        Logger.info("MsfDaemon: stopped")
    }

    /**
     * Stop the daemon, kill any msfrpcd (also ones from older app runs), move
     * legacy user data out of ruby/ and refuse start() until [endMaintenance].
     * Used before swapping the MSF bundle.
     */
    suspend fun beginMaintenance() {
        synchronized(lock) { maintenance = true }
        stop()
        val op = synchronized(lock) { lastOp }
        op?.join()
        withContext(Dispatchers.IO) {
            killOrphanedMsfrpcd()
            migrateMsfHome(toolManager, rootFs)
        }
    }

    fun endMaintenance() {
        synchronized(lock) { maintenance = false }
    }

    private fun isCurrent(gen: Long): Boolean = synchronized(lock) { gen == generation }

    /**
     * Apply [next] to the current state only if [gen] is still the active run.
     * [next] returning null leaves the state unchanged. Returns true if applied.
     */
    private inline fun transition(gen: Long, next: (DaemonState) -> DaemonState?): Boolean =
        synchronized(lock) {
            if (gen != generation) return false
            val target = next(_state.value) ?: return false
            _state.value = target
            if (target != DaemonState.READY) {
                sessionPollJob?.cancel()
                sessionPollJob = null
            }
            true
        }

    /**
     * Poll session.list every 5s while READY. Post a notification for each new
     * session id observed. Rolls forward the seen set so restarted sessions
     * (new id) re-trigger, but stale listings do not.
     */
    private fun startSessionPolling(gen: Long) {
        synchronized(lock) {
            if (gen != generation) return
            sessionPollJob?.cancel()
            sessionPollJob = scope.launch {
                val seenSessionIds = mutableSetOf<Int>()
                while (isActive && isCurrent(gen) && _state.value == DaemonState.READY) {
                    try {
                        notifyNewSessions(rpcClient, notifications, seenSessionIds)
                    } catch (e: CancellationException) {
                        throw e
                    } catch (_: Exception) {
                        // Transient RPC failure — keep polling.
                    }
                    delay(5000)
                }
            }
        }
    }

    private fun appendLog(line: String) {
        _logs.update { current ->
            val next = current + line
            if (next.size > 500) next.takeLast(500) else next
        }
    }
}

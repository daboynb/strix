package org.csploit.strix.data

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.csploit.strix.core.Logger
import org.csploit.strix.core.ProcessEvent
import org.csploit.strix.core.ProcessManager
import org.csploit.strix.core.StrixNotifications
import java.io.File
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
    // Singleton scope — survives beyond any single ViewModel
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    private val _state = MutableStateFlow(DaemonState.STOPPED)
    val state: StateFlow<DaemonState> = _state.asStateFlow()

    private val _logs = MutableStateFlow<List<String>>(emptyList())
    val logs: StateFlow<List<String>> = _logs.asStateFlow()

    private var processJob: Job? = null
    private var sessionPollJob: Job? = null
    private val seenSessionIds = mutableSetOf<Int>()

    val isRunning: Boolean get() = _state.value == DaemonState.READY

    /**
     * Start msfrpcd in foreground mode and wait until it accepts RPC calls.
     * Returns once daemon is READY or FAILED.
     */
    suspend fun start() {
        if (_state.value == DaemonState.STARTING || _state.value == DaemonState.READY) return

        _state.value = DaemonState.STARTING
        _logs.value = emptyList()

        // Kill any orphaned msfrpcd processes from previous sessions
        killOrphanedDaemons()

        val rubyPath = toolManager.rubyPath.trimEnd('/')
        val msfPath = toolManager.msfPath.trimEnd('/')
        val rubyBin = "$rubyPath/bin/ruby"
        val rubyApiVersion = detectRubyApiVersion(rubyPath) ?: "3.3.0"

        val user = appSettings.msfRpcUser
        val pass = appSettings.msfRpcPassword
        val port = appSettings.msfRpcPort
        val disableSslFlag = if (appSettings.msfRpcSsl) "" else " -S"

        // -f keeps msfrpcd in foreground so ProcessManager can track it
        val cmd = "$rubyBin $msfPath/msfrpcd -f -a 127.0.0.1 -p $port -U '$user' -P '$pass'$disableSslFlag"

        val env = mapOf(
            "HOME" to rubyPath,
            "PATH" to "$rubyPath/bin:$msfPath:/system/bin:/system/xbin",
            "LD_LIBRARY_PATH" to "$rubyPath/lib",
            "RUBYLIB" to "$rubyPath/lib/ruby/$rubyApiVersion:${detectArchDir(rubyPath, rubyApiVersion)}",
            "GEM_HOME" to "$msfPath/vendor/bundle/ruby/$rubyApiVersion",
            "GEM_PATH" to "$msfPath/vendor/bundle/ruby/$rubyApiVersion:$rubyPath/lib/ruby/gems/$rubyApiVersion",
            "OPENSSL_CONF" to "$rubyPath/ssl/openssl.cnf",
            "OPENSSL_MODULES" to "$rubyPath/lib/ossl-modules",
        )

        // Launch process watcher in singleton scope (lives beyond this suspend call)
        processJob = scope.launch(Dispatchers.IO) {
            processManager.execute(
                command = cmd,
                env = env,
                asSu = true,
            ).collect { event ->
                when (event) {
                    is ProcessEvent.StdoutLine -> appendLog(event.line)
                    is ProcessEvent.StderrLine -> appendLog(event.line)
                    is ProcessEvent.Exited -> {
                        appendLog("[daemon exited with code ${event.code}]")
                        if (_state.value != DaemonState.STOPPED) {
                            _state.value = if (event.code == 0) DaemonState.STOPPED else DaemonState.FAILED
                        }
                    }
                    is ProcessEvent.Killed -> {
                        appendLog("[daemon killed by signal ${event.signal}]")
                        _state.value = DaemonState.STOPPED
                    }
                }
            }
        }

        // Poll for readiness by attempting RPC connection
        withContext(Dispatchers.IO) {
            val timeout = 120_000L
            val startTime = System.currentTimeMillis()
            while (_state.value == DaemonState.STARTING) {
                if (System.currentTimeMillis() - startTime > timeout) {
                    _state.value = DaemonState.FAILED
                    appendLog("[timeout: daemon did not become ready within ${timeout / 1000}s]")
                    break
                }

                // Try connecting via RPC — more reliable than scraping log strings
                try {
                    rpcClient.configure(
                        host = appSettings.msfRpcHost,
                        port = appSettings.msfRpcPort,
                        ssl = appSettings.msfRpcSsl,
                    )
                    rpcClient.login(appSettings.msfRpcUser, appSettings.msfRpcPassword)
                    _state.value = DaemonState.READY
                    Logger.info("MsfDaemon: daemon is ready on port $port")
                    startSessionPolling()
                    break
                } catch (_: Exception) {
                    // Not ready yet, wait and retry
                    delay(2000)
                }
            }
        }
    }

    fun stop() {
        sessionPollJob?.cancel()
        sessionPollJob = null
        seenSessionIds.clear()
        processJob?.cancel()
        processJob = null
        rpcClient.disconnect()
        killOrphanedDaemons()
        _state.value = DaemonState.STOPPED
        appendLog("[daemon stopped]")
        Logger.info("MsfDaemon: stopped")
    }

    /**
     * Poll session.list every 5s while READY. Post a notification for each new
     * session id observed. Rolls forward the seen set so restarted sessions
     * (new id) re-trigger, but stale listings do not.
     */
    private fun startSessionPolling() {
        sessionPollJob?.cancel()
        sessionPollJob = scope.launch(Dispatchers.IO) {
            while (_state.value == DaemonState.READY) {
                try {
                    val sessions = rpcClient.sessionList()
                    for (s in sessions) {
                        if (seenSessionIds.add(s.id)) {
                            val info = buildString {
                                append(s.type)
                                if (s.targetHost.isNotEmpty()) append(" @ ${s.targetHost}")
                                if (s.viaExploit.isNotEmpty()) append(" via ${s.viaExploit}")
                            }
                            notifications.notifySessionOpened(s.id, info)
                            Logger.info("MsfDaemon: session opened #${s.id} $info")
                        }
                    }
                    // Drop ids that have closed so we re-notify if an id is reused.
                    val currentIds = sessions.map { it.id }.toSet()
                    seenSessionIds.retainAll(currentIds)
                } catch (_: Exception) {
                    // Transient RPC failure — keep polling.
                }
                delay(5000)
            }
        }
    }

    private fun killOrphanedDaemons() {
        try {
            val pb = ProcessBuilder("su", "-c", "pkill -f msfrpcd")
            val p = pb.start()
            p.waitFor()
            // Small delay to let the port be released
            Thread.sleep(500)
            Logger.info("MsfDaemon: killed orphaned msfrpcd processes")
        } catch (e: Exception) {
            Logger.debug("MsfDaemon: no orphaned processes to kill: ${e.message}")
        }
    }

    private fun detectRubyApiVersion(rubyPath: String): String? {
        val libDir = File(rubyPath, "lib/ruby")
        return libDir.listFiles()
            ?.firstOrNull { it.isDirectory && it.name.matches(Regex("\\d+\\.\\d+\\.\\d+")) }
            ?.name
    }

    /** Find the arch-specific directory (e.g. aarch64-linux-android-android) */
    private fun detectArchDir(rubyPath: String, apiVersion: String): String {
        val versionDir = File(rubyPath, "lib/ruby/$apiVersion")
        val archDir = versionDir.listFiles()
            ?.firstOrNull { it.isDirectory && it.name.startsWith("aarch64") }
            ?.absolutePath
        return archDir ?: "$rubyPath/lib/ruby/$apiVersion/aarch64-linux"
    }

    private fun appendLog(line: String) {
        val current = _logs.value.toMutableList()
        current.add(line)
        if (current.size > 500) {
            _logs.value = current.takeLast(500)
        } else {
            _logs.value = current
        }
    }
}

package org.csploit.strix.data

import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

data class MitmCapturedCredential(
    val protocol: String,
    val endpoint: String,
    val user: String,
    val pass: String,
)

data class MitmSession(
    val ip: String,
    val mode: MitmMode = MitmMode.SNIFFER,
    val isRunning: Boolean = false,
    val killActive: Boolean = false,
    val logLines: List<String> = emptyList(),
    val credentials: List<MitmCapturedCredential> = emptyList(),
    val error: String? = null,
)

/**
 * Keeps per-target MITM state in a singleton so the user can navigate away and
 * come back without losing the log / captured credentials. [MitmRunner] runs
 * the actual subprocesses; the VM orchestrates them and writes results here.
 */
@Singleton
class MitmSessionStore @Inject constructor() {
    companion object {
        private const val LOG_LIMIT = 200
    }

    private val _sessions = MutableStateFlow<Map<String, MitmSession>>(emptyMap())
    val sessions: StateFlow<Map<String, MitmSession>> = _sessions.asStateFlow()

    fun sessionOf(ip: String): MitmSession? = _sessions.value[ip]

    /**
     * In-flight teardown (kill-rule removal + iptables/sysctl cleanup) per host.
     * Lives here, not in the ViewModel, so a Start issued from a new VM instance
     * still waits for the cleanup started by the previous one.
     */
    private val teardowns = ConcurrentHashMap<String, Job>()

    fun setTeardown(ip: String, job: Job) {
        teardowns[ip] = job
        job.invokeOnCompletion { teardowns.remove(ip, job) }
    }

    fun teardownOf(ip: String): Job? = teardowns[ip]

    fun clear(ip: String) {
        _sessions.update { it - ip }
    }

    fun setRunning(ip: String, mode: MitmMode, running: Boolean) {
        update(ip) { it.copy(isRunning = running, mode = mode) }
    }

    fun setKillActive(ip: String, active: Boolean) {
        update(ip) { it.copy(killActive = active) }
    }

    fun appendLog(ip: String, line: String) {
        update(ip) {
            val next = it.logLines + line
            it.copy(logLines = if (next.size > LOG_LIMIT) next.takeLast(LOG_LIMIT) else next)
        }
    }

    /** Returns true if the credential was new and added. */
    fun addCredential(ip: String, cred: MitmCapturedCredential): Boolean {
        var added = false
        update(ip) { s ->
            // Reset on every attempt: update {} may re-run the lambda on contention.
            added = false
            if (s.credentials.any { it.user == cred.user && it.pass == cred.pass && it.protocol == cred.protocol }) {
                s
            } else {
                added = true
                s.copy(credentials = s.credentials + cred)
            }
        }
        return added
    }

    fun setError(ip: String, message: String?) {
        update(ip) { it.copy(error = message) }
    }

    fun resetForNewRun(ip: String, mode: MitmMode) {
        _sessions.update { it + (ip to MitmSession(ip = ip, mode = mode, isRunning = true)) }
    }

    /** Atomic read-modify-write: callers run on Main, IO and DnsSpoofServer threads. */
    private inline fun update(ip: String, crossinline transform: (MitmSession) -> MitmSession) {
        _sessions.update { current ->
            val existing = current[ip] ?: MitmSession(ip = ip)
            current + (ip to transform(existing))
        }
    }
}

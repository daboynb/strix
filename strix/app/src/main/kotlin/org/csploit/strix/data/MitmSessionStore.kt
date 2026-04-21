package org.csploit.strix.data

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
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

    fun clear(ip: String) {
        _sessions.value = _sessions.value - ip
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
        _sessions.value = _sessions.value + (ip to MitmSession(ip = ip, mode = mode, isRunning = true))
    }

    private inline fun update(ip: String, transform: (MitmSession) -> MitmSession) {
        val current = _sessions.value
        val existing = current[ip] ?: MitmSession(ip = ip)
        _sessions.value = current + (ip to transform(existing))
    }
}

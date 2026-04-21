package org.csploit.strix.data

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

data class BruteForceSession(
    val key: String,
    val ip: String,
    val port: Int,
    val method: String,
    val isRunning: Boolean = false,
    val logLines: List<String> = emptyList(),
    val foundCreds: String? = null,
    val statusLine: String? = null,
    val progress: Float? = null,
)

/**
 * Per-attack state for hydra brute-force runs. Keyed by "ip:port:method" so
 * multiple concurrent attacks on different targets/methods don't collide.
 */
@Singleton
class BruteForceSessionStore @Inject constructor() {
    companion object {
        private const val LOG_LIMIT = 50

        fun keyFor(ip: String, port: Int, method: String) = "$ip:$port:$method"
    }

    private val _sessions = MutableStateFlow<Map<String, BruteForceSession>>(emptyMap())
    val sessions: StateFlow<Map<String, BruteForceSession>> = _sessions.asStateFlow()

    fun sessionOf(key: String): BruteForceSession? = _sessions.value[key]

    fun clear(key: String) {
        _sessions.value = _sessions.value - key
    }

    fun resetForNewRun(key: String, ip: String, port: Int, method: String) {
        _sessions.value = _sessions.value + (key to BruteForceSession(
            key = key, ip = ip, port = port, method = method, isRunning = true,
        ))
    }

    fun setRunning(key: String, running: Boolean) {
        update(key) { it.copy(isRunning = running) }
    }

    fun appendLog(key: String, line: String) {
        update(key) {
            val next = it.logLines + line
            it.copy(logLines = if (next.size > LOG_LIMIT) next.takeLast(LOG_LIMIT) else next)
        }
    }

    fun setFoundCreds(key: String, creds: String?) {
        update(key) { it.copy(foundCreds = creds) }
    }

    fun setStatus(key: String, line: String?, progress: Float?) {
        update(key) { it.copy(statusLine = line, progress = progress) }
    }

    private inline fun update(key: String, transform: (BruteForceSession) -> BruteForceSession) {
        val current = _sessions.value
        val existing = current[key] ?: BruteForceSession(
            key = key, ip = "", port = 0, method = "",
        )
        _sessions.value = current + (key to transform(existing))
    }
}

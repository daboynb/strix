package org.csploit.strix.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.csploit.strix.domain.model.MsfSession

// --- Session Operations ---

suspend fun MsfRpcClient.sessionList(): List<MsfSession> = withContext(Dispatchers.IO) {
    val result = callAuthenticated("session.list") as? Map<*, *> ?: return@withContext emptyList()

    result.mapNotNull { (key, value) ->
        val id = when (key) {
            is Number -> key.toInt()
            is String -> key.toIntOrNull()
            else -> null
        } ?: return@mapNotNull null

        val info = value as? Map<*, *> ?: return@mapNotNull null

        MsfSession(
            id = id,
            type = info["type"]?.toString() ?: "unknown",
            info = info["info"]?.toString() ?: "",
            targetHost = info["target_host"]?.toString()
                ?: info["session_host"]?.toString() ?: "",
            targetPort = (info["session_port"] as? Number)?.toInt() ?: 0,
            viaExploit = info["via_exploit"]?.toString() ?: "",
            viaPayload = info["via_payload"]?.toString() ?: "",
            username = info["username"]?.toString() ?: "",
            uuid = info["uuid"]?.toString() ?: "",
        )
    }
}

suspend fun MsfRpcClient.sessionStop(sessionId: Int) = withContext(Dispatchers.IO) {
    callAuthenticated("session.stop", sessionId)
}

suspend fun MsfRpcClient.shellWrite(sessionId: Int, command: String) = withContext(Dispatchers.IO) {
    callAuthenticated("session.shell_write", sessionId, command)
}

suspend fun MsfRpcClient.shellRead(sessionId: Int): String = withContext(Dispatchers.IO) {
    val result = callAuthenticated("session.shell_read", sessionId) as? Map<*, *>
    result?.get("data")?.toString() ?: ""
}

// --- Meterpreter session operations ---
// https://docs.rapid7.com/metasploit/standard-api-methods-reference/

/** Buffers a Meterpreter console command; output is retrieved via [meterpreterRead]. */
suspend fun MsfRpcClient.meterpreterWrite(sessionId: Int, command: String) = withContext(Dispatchers.IO) {
    callAuthenticated("session.meterpreter_write", sessionId, command)
}

/** Drains accumulated Meterpreter console output since the last read. */
suspend fun MsfRpcClient.meterpreterRead(sessionId: Int): String = withContext(Dispatchers.IO) {
    val result = callAuthenticated("session.meterpreter_read", sessionId) as? Map<*, *>
    result?.get("data")?.toString() ?: ""
}

/** Runs a single Meterpreter command (no trailing newline required). */
suspend fun MsfRpcClient.meterpreterRunSingle(sessionId: Int, command: String) = withContext(Dispatchers.IO) {
    callAuthenticated("session.meterpreter_run_single", sessionId, command)
}

package org.csploit.strix.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

// --- Console (for exploit output capture) ---

suspend fun MsfRpcClient.consoleCreate(): Int = withContext(Dispatchers.IO) {
    val result = callAuthenticated("console.create") as? Map<*, *>
        ?: throw MsfRpcException("console.create failed")
    (result["id"] as? Number)?.toInt()
        ?: result["id"]?.toString()?.toIntOrNull()
        ?: throw MsfRpcException("No console id")
}

suspend fun MsfRpcClient.consoleWrite(consoleId: Int, command: String) = withContext(Dispatchers.IO) {
    callAuthenticated("console.write", consoleId, command)
}

suspend fun MsfRpcClient.consoleRead(consoleId: Int): MsfRpcClient.ConsoleOutput = withContext(Dispatchers.IO) {
    val result = callAuthenticated("console.read", consoleId) as? Map<*, *>
        ?: return@withContext MsfRpcClient.ConsoleOutput("", false)
    MsfRpcClient.ConsoleOutput(
        data = result["data"]?.toString() ?: "",
        busy = result["busy"].asMsfBool(),
    )
}

suspend fun MsfRpcClient.consoleDestroy(consoleId: Int) = withContext(Dispatchers.IO) {
    callAuthenticated("console.destroy", consoleId)
}

// --- Core ---

suspend fun MsfRpcClient.coreVersion(): Map<String, String> = withContext(Dispatchers.IO) {
    val result = callAuthenticated("core.version") as? Map<*, *>
        ?: return@withContext emptyMap()
    result.mapKeys { it.key.toString() }.mapValues { it.value?.toString() ?: "" }
}

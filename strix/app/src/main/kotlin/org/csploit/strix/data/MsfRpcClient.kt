package org.csploit.strix.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.csploit.strix.core.Logger
import javax.inject.Inject
import javax.inject.Singleton

private const val DEFAULT_READ_TIMEOUT_MS = 30_000
internal const val EXPLOIT_READ_TIMEOUT_MS = 300_000

/**
 * msfrpcd client: connection state, authentication and the msgpack transport.
 * Typed RPC groups live in MsfRpcModules.kt, MsfRpcSessions.kt and MsfRpcConsole.kt.
 */
@Singleton
class MsfRpcClient @Inject constructor() {

    private var host: String = "127.0.0.1"
    private var port: Int = 55553
    private var ssl: Boolean = false
    private var token: String? = null
    private val mutex = Mutex()
    internal val cache = java.util.concurrent.ConcurrentHashMap<String, Any?>()

    val isAuthenticated: Boolean get() = token != null

    fun configure(host: String, port: Int, ssl: Boolean) {
        this.host = host
        this.port = port
        this.ssl = ssl
        this.token = null
        cache.clear()
    }

    fun disconnect() {
        token = null
        cache.clear()
    }

    // --- Authentication ---

    suspend fun login(username: String, password: String): Boolean = withContext(Dispatchers.IO) {
        val result = call("auth.login", username, password) as? Map<*, *>
            ?: throw MsfRpcException("Invalid login response")

        if (result.containsKey("error")) {
            throw MsfRpcException(
                result["error_message"]?.toString() ?: "Login failed",
                result["error_class"]?.toString(),
            )
        }

        token = result["token"]?.toString()
            ?: throw MsfRpcException("No token in login response")

        Logger.info("MsfRpcClient: authenticated, token=${token?.take(8)}...")
        true
    }

    data class ConsoleOutput(val data: String, val busy: Boolean)

    /** Decode msfrpcd's msgpack error body; null if it isn't one. */
    internal fun parseErrorBody(body: ByteArray): RpcError? = parseRpcErrorBody(body)

    // --- Transport Layer ---

    internal suspend fun callAuthenticated(method: String, vararg args: Any?): Any? =
        callAuthenticatedWithTimeout(method, DEFAULT_READ_TIMEOUT_MS, *args)

    internal suspend fun callAuthenticatedWithTimeout(
        method: String,
        readTimeoutMs: Int,
        vararg args: Any?,
    ): Any? {
        val t = token ?: throw MsfRpcException("Not authenticated")
        return callWithTimeout(method, readTimeoutMs, t, *args)
    }

    private suspend fun call(method: String, vararg args: Any?): Any? =
        callWithTimeout(method, DEFAULT_READ_TIMEOUT_MS, *args)

    private suspend fun callWithTimeout(
        method: String,
        readTimeoutMs: Int,
        vararg args: Any?,
    ): Any? = mutex.withLock {
        val requestBody = MsfMsgPack.packRequest(method, *args)
        val conn = openRpcConnection(host, port, ssl, readTimeoutMs, requestBody.size)

        try {
            conn.outputStream.use { it.write(requestBody) }

            val status = conn.responseCode
            if (status != 200) {
                val error = msfHttpError(method, status, conn)
                // Token expired/invalid — clear it so callers re-authenticate
                if (error.tokenRejected) token = null
                throw error
            }

            val responseBytes = conn.inputStream.use { it.readBytes() }
            val result = MsfMsgPack.unpackResponse(responseBytes)

            // Check for RPC-level errors
            if (result is Map<*, *> && result.containsKey("error") && result["error"] == true) {
                throw MsfRpcException(
                    result["error_message"]?.toString() ?: "RPC error",
                    result["error_class"]?.toString(),
                )
            }

            result
        } finally {
            conn.disconnect()
        }
    }
}

package org.csploit.strix.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.csploit.strix.core.Logger
import org.csploit.strix.domain.model.ExploitRank
import org.csploit.strix.domain.model.MsfModuleInfo
import org.csploit.strix.domain.model.MsfOption
import org.csploit.strix.domain.model.MsfSession
import org.msgpack.core.MessagePack
import org.msgpack.core.MessageUnpacker
import org.msgpack.value.ValueType
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.inject.Inject
import javax.inject.Singleton
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

class MsfRpcException(message: String, val errorClass: String? = null) : Exception(message)

private const val DEFAULT_READ_TIMEOUT_MS = 30_000
private const val EXPLOIT_READ_TIMEOUT_MS = 300_000

@Singleton
class MsfRpcClient @Inject constructor() {

    private var host: String = "127.0.0.1"
    private var port: Int = 55553
    private var ssl: Boolean = false
    private var token: String? = null
    private val mutex = Mutex()
    private val cache = java.util.concurrent.ConcurrentHashMap<String, Any?>()

    private val trustAllSslFactory by lazy {
        val tm = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, arrayOf<TrustManager>(tm), SecureRandom())
        ctx.socketFactory
    }

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

    // --- Module Operations ---

    suspend fun moduleSearch(query: String): List<Map<String, Any?>> = withContext(Dispatchers.IO) {
        val result = callAuthenticated("module.search", query)
        // MSF returns {modules: [...]} or directly a list depending on version
        @Suppress("UNCHECKED_CAST")
        when (result) {
            is List<*> -> result.filterIsInstance<Map<String, Any?>>()
            is Map<*, *> -> (result["modules"] as? List<*>)
                ?.filterIsInstance<Map<String, Any?>>() ?: emptyList()
            else -> emptyList()
        }
    }

    suspend fun moduleInfo(type: String, name: String): MsfModuleInfo = withContext(Dispatchers.IO) {
        val cacheKey = "module.info:$type:$name"
        cache[cacheKey]?.let {
            @Suppress("UNCHECKED_CAST")
            return@withContext it as MsfModuleInfo
        }

        val result = callAuthenticated("module.info", type, name) as? Map<*, *>
            ?: throw MsfRpcException("Invalid module.info response")

        val rank = when (val r = result["rank"]) {
            is Number -> ExploitRank.fromValue(r.toInt())
            is String -> ExploitRank.fromString(r)
            else -> ExploitRank.Manual
        }

        @Suppress("UNCHECKED_CAST")
        val targets = (result["targets"] as? Map<*, *>)
            ?.mapKeys { (k, _) -> (k as? Number)?.toInt() ?: k.toString().toIntOrNull() ?: 0 }
            ?.mapValues { (_, v) -> v.toString() }
            ?: emptyMap()

        @Suppress("UNCHECKED_CAST")
        val refs = (result["references"] as? List<*>)
            ?.filterIsInstance<List<*>>()
            ?.map { it.map { e -> e.toString() } }
            ?: emptyList()

        val authors = (result["authors"] as? List<*>)
            ?.map { it.toString() }
            ?: emptyList()

        val info = MsfModuleInfo(
            fullName = name,
            type = type,
            name = result["name"]?.toString() ?: name.substringAfterLast('/'),
            description = result["description"]?.toString()?.trim() ?: "",
            rank = rank,
            references = refs,
            authors = authors,
            targets = targets,
            defaultTarget = (result["default_target"] as? Number)?.toInt() ?: 0,
        )

        cache[cacheKey] = info
        info
    }

    suspend fun moduleOptions(type: String, name: String): List<MsfOption> =
        withContext(Dispatchers.IO) {
            val cacheKey = "module.options:$type:$name"
            cache[cacheKey]?.let {
                @Suppress("UNCHECKED_CAST")
                return@withContext it as List<MsfOption>
            }

            val result = callAuthenticated("module.options", type, name) as? Map<*, *>
                ?: throw MsfRpcException("Invalid module.options response")

            val options = result.mapNotNull { (key, value) ->
                val optMap = value as? Map<*, *> ?: return@mapNotNull null
                MsfOption(
                    name = key.toString(),
                    type = optMap["type"]?.toString() ?: "string",
                    required = optMap["required"].asBool(),
                    description = optMap["desc"]?.toString() ?: "",
                    default = optMap["default"]?.toString(),
                    enums = (optMap["enums"] as? List<*>)?.map { it.toString() },
                    advanced = optMap["advanced"].asBool(),
                    evasion = optMap["evasion"].asBool(),
                )
            }

            cache[cacheKey] = options
            options
        }

    suspend fun compatiblePayloads(exploitName: String): List<String> =
        withContext(Dispatchers.IO) {
            val cacheKey = "module.compatible_payloads:$exploitName"
            cache[cacheKey]?.let {
                @Suppress("UNCHECKED_CAST")
                return@withContext it as List<String>
            }

            val result = callAuthenticated("module.compatible_payloads", exploitName) as? Map<*, *>
                ?: throw MsfRpcException("Invalid compatible_payloads response")

            val payloads = (result["payloads"] as? List<*>)
                ?.map { it.toString() }
                ?: emptyList()

            cache[cacheKey] = payloads
            payloads
        }

    suspend fun moduleExecute(
        type: String,
        name: String,
        options: Map<String, Any>,
    ): Map<String, Any?> = withContext(Dispatchers.IO) {
        Logger.info("MsfRpcClient: module.execute type=$type name=$name options=$options")
        // Module execution can take minutes: socket setup, payload delivery, session
        // handshake. The default 30s read timeout is way too short — bump for this call.
        val result = callAuthenticatedWithTimeout(
            "module.execute", EXPLOIT_READ_TIMEOUT_MS, type, name, options,
        ) as? Map<*, *>
            ?: throw MsfRpcException("Invalid module.execute response")
        Logger.info("MsfRpcClient: module.execute result=$result")

        if (result["error"] == true) {
            throw MsfRpcException(
                result["error_message"]?.toString() ?: "Execution failed",
            )
        }

        result.mapKeys { it.key.toString() }.mapValues { it.value }
    }

    // --- Session Operations ---

    suspend fun sessionList(): List<MsfSession> = withContext(Dispatchers.IO) {
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

    suspend fun sessionStop(sessionId: Int) = withContext(Dispatchers.IO) {
        callAuthenticated("session.stop", sessionId)
    }

    suspend fun shellWrite(sessionId: Int, command: String) = withContext(Dispatchers.IO) {
        callAuthenticated("session.shell_write", sessionId, command)
    }

    suspend fun shellRead(sessionId: Int): String = withContext(Dispatchers.IO) {
        val result = callAuthenticated("session.shell_read", sessionId) as? Map<*, *>
        result?.get("data")?.toString() ?: ""
    }

    // --- Meterpreter session operations ---
    // https://docs.rapid7.com/metasploit/standard-api-methods-reference/

    /** Buffers a Meterpreter console command; output is retrieved via [meterpreterRead]. */
    suspend fun meterpreterWrite(sessionId: Int, command: String) = withContext(Dispatchers.IO) {
        callAuthenticated("session.meterpreter_write", sessionId, command)
    }

    /** Drains accumulated Meterpreter console output since the last read. */
    suspend fun meterpreterRead(sessionId: Int): String = withContext(Dispatchers.IO) {
        val result = callAuthenticated("session.meterpreter_read", sessionId) as? Map<*, *>
        result?.get("data")?.toString() ?: ""
    }

    /** Runs a single Meterpreter command (no trailing newline required). */
    suspend fun meterpreterRunSingle(sessionId: Int, command: String) = withContext(Dispatchers.IO) {
        callAuthenticated("session.meterpreter_run_single", sessionId, command)
    }

    // --- Console (for exploit output capture) ---

    suspend fun consoleCreate(): Int = withContext(Dispatchers.IO) {
        val result = callAuthenticated("console.create") as? Map<*, *>
            ?: throw MsfRpcException("console.create failed")
        (result["id"] as? Number)?.toInt()
            ?: result["id"]?.toString()?.toIntOrNull()
            ?: throw MsfRpcException("No console id")
    }

    suspend fun consoleWrite(consoleId: Int, command: String) = withContext(Dispatchers.IO) {
        callAuthenticated("console.write", consoleId, command)
    }

    suspend fun consoleRead(consoleId: Int): ConsoleOutput = withContext(Dispatchers.IO) {
        val result = callAuthenticated("console.read", consoleId) as? Map<*, *>
            ?: return@withContext ConsoleOutput("", false)
        ConsoleOutput(
            data = result["data"]?.toString() ?: "",
            busy = result["busy"].asBool(),
        )
    }

    suspend fun consoleDestroy(consoleId: Int) = withContext(Dispatchers.IO) {
        callAuthenticated("console.destroy", consoleId)
    }

    data class ConsoleOutput(val data: String, val busy: Boolean)

    // --- Core ---

    suspend fun coreVersion(): Map<String, String> = withContext(Dispatchers.IO) {
        val result = callAuthenticated("core.version") as? Map<*, *>
            ?: return@withContext emptyMap()
        result.mapKeys { it.key.toString() }.mapValues { it.value?.toString() ?: "" }
    }

    // MSF sometimes sends booleans as binary strings
    private fun Any?.asBool(): Boolean = when (this) {
        is Boolean -> this
        is String -> this.equals("true", ignoreCase = true)
        else -> false
    }

    // --- Transport Layer ---

    private suspend fun callAuthenticated(method: String, vararg args: Any?): Any? =
        callAuthenticatedWithTimeout(method, DEFAULT_READ_TIMEOUT_MS, *args)

    private suspend fun callAuthenticatedWithTimeout(
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
        val requestBody = packRequest(method, *args)
        val scheme = if (ssl) "https" else "http"
        val url = URL("$scheme://$host:$port/api/")

        val conn = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            doInput = true
            connectTimeout = 10_000
            readTimeout = readTimeoutMs
            setRequestProperty("Content-Type", "binary/message-pack")
            setRequestProperty("Content-Length", requestBody.size.toString())

            if (this is HttpsURLConnection) {
                sslSocketFactory = trustAllSslFactory
                setHostnameVerifier { _, _ -> true }
            }
        }

        try {
            conn.outputStream.use { it.write(requestBody) }

            if (conn.responseCode == 401) {
                // Token expired — clear it so ensureDaemon re-authenticates
                token = null
                throw MsfRpcException("HTTP 401: Token expired")
            }
            if (conn.responseCode != 200) {
                throw MsfRpcException("HTTP ${conn.responseCode}: ${conn.responseMessage}")
            }

            val responseBytes = conn.inputStream.use { it.readBytes() }
            val result = unpackResponse(responseBytes)

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

    // --- MessagePack Serialization ---

    private fun packRequest(method: String, vararg args: Any?): ByteArray {
        val baos = ByteArrayOutputStream()
        val packer = MessagePack.newDefaultPacker(baos)

        // RPC request is an array: [method, args...]
        packer.packArrayHeader(1 + args.size)
        packer.packString(method)

        for (arg in args) {
            packValue(packer, arg)
        }

        packer.flush()
        return baos.toByteArray()
    }

    private fun packValue(packer: org.msgpack.core.MessagePacker, value: Any?) {
        when (value) {
            null -> packer.packNil()
            is String -> packer.packString(value)
            is Int -> packer.packInt(value)
            is Long -> packer.packLong(value)
            is Boolean -> packer.packBoolean(value)
            is Float -> packer.packFloat(value)
            is Double -> packer.packDouble(value)
            is ByteArray -> {
                packer.packBinaryHeader(value.size)
                packer.writePayload(value)
            }
            is Map<*, *> -> {
                packer.packMapHeader(value.size)
                for ((k, v) in value) {
                    packValue(packer, k)
                    packValue(packer, v)
                }
            }
            is List<*> -> {
                packer.packArrayHeader(value.size)
                for (item in value) {
                    packValue(packer, item)
                }
            }
            is Array<*> -> {
                packer.packArrayHeader(value.size)
                for (item in value) {
                    packValue(packer, item)
                }
            }
            else -> packer.packString(value.toString())
        }
    }

    private fun unpackResponse(data: ByteArray): Any? {
        val unpacker = MessagePack.newDefaultUnpacker(data)
        return if (unpacker.hasNext()) unpackValue(unpacker) else null
    }

    private fun unpackValue(unpacker: MessageUnpacker): Any? {
        val format = unpacker.nextFormat
        return when (format.valueType) {
            ValueType.NIL -> { unpacker.unpackNil(); null }
            ValueType.BOOLEAN -> unpacker.unpackBoolean()
            ValueType.INTEGER -> {
                val v = unpacker.unpackValue()
                if (v.isIntegerValue) {
                    val lv = v.asIntegerValue().toLong()
                    if (lv in Int.MIN_VALUE..Int.MAX_VALUE) lv.toInt() else lv
                } else v
            }
            ValueType.FLOAT -> unpacker.unpackDouble()
            ValueType.STRING -> unpacker.unpackString()
            ValueType.BINARY -> {
                // MSF often sends strings as binary
                val len = unpacker.unpackBinaryHeader()
                val bytes = ByteArray(len)
                unpacker.readPayload(bytes)
                String(bytes, Charsets.UTF_8)
            }
            ValueType.ARRAY -> {
                val size = unpacker.unpackArrayHeader()
                (0 until size).map { unpackValue(unpacker) }
            }
            ValueType.MAP -> {
                val size = unpacker.unpackMapHeader()
                val map = LinkedHashMap<String, Any?>(size)
                repeat(size) {
                    val key = unpackValue(unpacker)?.toString() ?: ""
                    val value = unpackValue(unpacker)
                    map[key] = value
                }
                map
            }
            ValueType.EXTENSION -> {
                val ext = unpacker.unpackValue()
                ext.toString()
            }
            else -> {
                unpacker.skipValue()
                null
            }
        }
    }
}

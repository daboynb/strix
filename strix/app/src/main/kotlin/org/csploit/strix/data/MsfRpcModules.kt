package org.csploit.strix.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.csploit.strix.core.Logger
import org.csploit.strix.domain.model.ExploitRank
import org.csploit.strix.domain.model.MsfModuleInfo
import org.csploit.strix.domain.model.MsfOption

// --- Module Operations ---

suspend fun MsfRpcClient.moduleSearch(query: String): List<Map<String, Any?>> = withContext(Dispatchers.IO) {
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

suspend fun MsfRpcClient.moduleInfo(type: String, name: String): MsfModuleInfo = withContext(Dispatchers.IO) {
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

suspend fun MsfRpcClient.moduleOptions(type: String, name: String): List<MsfOption> =
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
                required = optMap["required"].asMsfBool(),
                description = optMap["desc"]?.toString() ?: "",
                default = optMap["default"]?.toString(),
                enums = (optMap["enums"] as? List<*>)?.map { it.toString() },
                advanced = optMap["advanced"].asMsfBool(),
                evasion = optMap["evasion"].asMsfBool(),
            )
        }

        cache[cacheKey] = options
        options
    }

suspend fun MsfRpcClient.compatiblePayloads(exploitName: String): List<String> =
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

suspend fun MsfRpcClient.moduleExecute(
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

package org.csploit.strix.data

import java.net.HttpURLConnection

class MsfRpcException(
    message: String,
    val errorClass: String? = null,
    /** HTTP status returned by msfrpcd, null for transport/parse-level failures. */
    val httpStatus: Int? = null,
    /** True when msfrpcd rejected the session token (not a bad login). */
    val tokenRejected: Boolean = false,
) : Exception(message)

internal data class RpcError(val message: String?, val errorClass: String?)

/**
 * msfrpcd reports failures as a non-200 status with a msgpack body
 * {error, error_class, error_string, error_message, ...}. 401 means either
 * a bad auth.login (wrong user/password) or a rejected token; only the
 * latter invalidates our token (signalled via [MsfRpcException.tokenRejected]).
 */
internal fun msfHttpError(method: String, status: Int, conn: HttpURLConnection): MsfRpcException {
    val body = try {
        conn.errorStream?.use { it.readBytes() }
    } catch (_: java.io.IOException) {
        null
    }
    val err = body?.let { parseRpcErrorBody(it) }
    val detail = err?.message ?: conn.responseMessage ?: "HTTP $status"

    if (status == 401 && method == "auth.login") {
        return MsfRpcException("Login failed: $detail", err?.errorClass, status)
    }
    if (status == 401) {
        return MsfRpcException(
            "Authentication token rejected: $detail", err?.errorClass, status, tokenRejected = true,
        )
    }
    return MsfRpcException("$method failed (HTTP $status): $detail", err?.errorClass, status)
}

/** Decode msfrpcd's msgpack error body; null if it isn't one. */
internal fun parseRpcErrorBody(body: ByteArray): RpcError? {
    val map = try {
        MsfMsgPack.unpackResponse(body) as? Map<*, *>
    } catch (_: Exception) {
        null
    } ?: return null
    val message = (map["error_message"] ?: map["error_string"])?.toString()?.takeIf { it.isNotBlank() }
    val errorClass = map["error_class"]?.toString()?.takeIf { it.isNotBlank() }
    if (message == null && errorClass == null) return null
    return RpcError(message, errorClass)
}

// MSF sometimes sends booleans as binary strings
internal fun Any?.asMsfBool(): Boolean = when (this) {
    is Boolean -> this
    is String -> this.equals("true", ignoreCase = true)
    else -> false
}

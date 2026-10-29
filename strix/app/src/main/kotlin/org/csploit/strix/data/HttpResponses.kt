package org.csploit.strix.data

import org.csploit.strix.core.Logger
import java.io.ByteArrayOutputStream
import java.net.Socket
import java.net.SocketTimeoutException

/** Raw HTTP response reading and fingerprint parsing for [HttpProbe]. */
internal object HttpResponses {
    private const val MAX_RESPONSE = 8192
    private val TITLE_END = Regex("</title>", RegexOption.IGNORE_CASE)
    private val CONTENT_LENGTH = Regex("(?im)^Content-Length:\\s*(\\d+)")

    /**
     * Reads the status line, headers and at most [MAX_RESPONSE] bytes total.
     * Stops as soon as the body is complete (Content-Length) or the <title> has
     * been received, so keep-alive servers that ignore "Connection: close" don't
     * hold us until the read timeout. On timeout, whatever arrived is kept.
     */
    fun readResponse(socket: Socket): String {
        val input = socket.getInputStream()
        val received = ByteArrayOutputStream()
        val buf = ByteArray(2048)
        try {
            while (received.size() < MAX_RESPONSE) {
                val n = input.read(buf, 0, minOf(buf.size, MAX_RESPONSE - received.size()))
                if (n == -1) break
                received.write(buf, 0, n)
                if (isComplete(received.toString(Charsets.UTF_8.name()))) break
            }
        } catch (_: SocketTimeoutException) {
            // Keep the partial response: headers alone are enough to fingerprint.
        }
        return received.toString(Charsets.UTF_8.name())
    }

    private fun isComplete(text: String): Boolean {
        val headerEnd = text.indexOf("\r\n\r\n")
        if (headerEnd < 0) return false
        val body = text.substring(headerEnd + 4)
        if (TITLE_END.containsMatchIn(body)) return true
        val contentLength = CONTENT_LENGTH.find(text.substring(0, headerEnd))
            ?.groupValues?.get(1)?.toIntOrNull() ?: return false
        return body.toByteArray(Charsets.UTF_8).size >= contentLength
    }

    fun parseResponse(response: String, ip: String, port: Int, useSsl: Boolean): HttpFingerprintResult? {
        val statusLine = response.lineSequence().firstOrNull() ?: return null
        val statusCode = Regex("\\d{3}").find(statusLine)?.value?.toIntOrNull()

        val headerEnd = response.indexOf("\r\n\r\n")
        val headers = if (headerEnd > 0) response.substring(0, headerEnd) else response
        val body = if (headerEnd > 0) response.substring(headerEnd + 4) else ""

        val server = Regex("Server:\\s*(.+)", RegexOption.IGNORE_CASE)
            .find(headers)?.groupValues?.get(1)?.trim()
        val wwwAuth = Regex("WWW-Authenticate:\\s*(.+)", RegexOption.IGNORE_CASE)
            .find(headers)?.groupValues?.get(1)?.trim()
        val title = Regex("<title[^>]*>(.*?)</title>", RegexOption.IGNORE_CASE)
            .find(body)?.groupValues?.get(1)?.trim()?.ifBlank { null }

        val scheme = if (useSsl) "https" else "http"
        Logger.info("HttpProbe: $scheme://$ip:$port => status=$statusCode server=$server title=$title")

        return HttpFingerprintResult(
            adminUrl = "$scheme://$ip:$port/",
            serverHeader = server,
            title = title,
            wwwAuthenticate = wwwAuth,
            statusCode = statusCode,
        )
    }
}

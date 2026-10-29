package org.csploit.strix.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.csploit.strix.core.Logger
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

data class HttpFingerprintResult(
    val adminUrl: String? = null,
    val serverHeader: String? = null,
    val title: String? = null,
    val wwwAuthenticate: String? = null,
    val statusCode: Int? = null,
)

@Singleton
class HttpProbe @Inject constructor() {

    /**
     * Probe HTTP/HTTPS ports via raw socket.
     * Handles non-standard responses that HttpURLConnection rejects.
     */
    suspend fun fingerprint(ip: String, ports: List<Int>): HttpFingerprintResult = withContext(Dispatchers.IO) {
        for (port in ports) {
            try {
                val useSsl = port == 443 || port == 8443
                val socket = if (useSsl) {
                    trustAllSslFactory().createSocket()
                } else {
                    Socket()
                }
                // use{} closes the socket on every path (connect failure,
                // read timeout, parse error), not only on success.
                val response = socket.use {
                    it.connect(InetSocketAddress(ip, port), 3000)
                    it.soTimeout = 3000

                    val request = "GET / HTTP/1.1\r\nHost: $ip\r\nConnection: close\r\n\r\n"
                    it.getOutputStream().write(request.toByteArray())
                    it.getOutputStream().flush()

                    readResponse(it)
                }

                if (response.isEmpty()) continue

                val result = parseResponse(response, ip, port, useSsl) ?: continue
                return@withContext result
            } catch (e: Exception) {
                val scheme = if (port == 443 || port == 8443) "https" else "http"
                Logger.debug("HttpProbe: $scheme://$ip:$port failed: ${e.message}")
            }
        }
        HttpFingerprintResult()
    }

    /**
     * Reads the status line, headers and at most [MAX_RESPONSE] bytes total.
     * Stops as soon as the body is complete (Content-Length) or the <title> has
     * been received, so keep-alive servers that ignore "Connection: close" don't
     * hold us until the read timeout. On timeout, whatever arrived is kept.
     */
    private fun readResponse(socket: Socket): String {
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

    private fun parseResponse(response: String, ip: String, port: Int, useSsl: Boolean): HttpFingerprintResult? {
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

    private fun trustAllSslFactory(): javax.net.ssl.SSLSocketFactory {
        val tm = arrayOf<javax.net.ssl.TrustManager>(object : javax.net.ssl.X509TrustManager {
            override fun checkClientTrusted(c: Array<java.security.cert.X509Certificate>, a: String) {}
            override fun checkServerTrusted(c: Array<java.security.cert.X509Certificate>, a: String) {}
            override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = arrayOf()
        })
        val ctx = javax.net.ssl.SSLContext.getInstance("TLS")
        ctx.init(null, tm, java.security.SecureRandom())
        return ctx.socketFactory
    }

    private companion object {
        const val MAX_RESPONSE = 8192
        val TITLE_END = Regex("</title>", RegexOption.IGNORE_CASE)
        val CONTENT_LENGTH = Regex("(?im)^Content-Length:\\s*(\\d+)")
    }
}

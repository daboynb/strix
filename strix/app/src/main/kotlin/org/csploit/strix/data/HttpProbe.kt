package org.csploit.strix.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.csploit.strix.core.Logger
import java.net.InetSocketAddress
import java.net.Socket
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
                socket.connect(InetSocketAddress(ip, port), 3000)
                socket.soTimeout = 3000

                val request = "GET / HTTP/1.1\r\nHost: $ip\r\nConnection: close\r\n\r\n"
                socket.getOutputStream().write(request.toByteArray())
                socket.getOutputStream().flush()

                val response = socket.getInputStream().bufferedReader()
                    .use { it.readText().take(8192) }
                socket.close()

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
}

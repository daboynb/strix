package org.csploit.strix.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.csploit.strix.core.Logger
import org.csploit.strix.data.HttpResponses.parseResponse
import org.csploit.strix.data.HttpResponses.readResponse
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

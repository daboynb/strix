package org.csploit.strix.data

import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

private val trustAllSslFactory: SSLSocketFactory by lazy {
    val tm = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }
    val ctx = SSLContext.getInstance("TLS")
    ctx.init(null, arrayOf<TrustManager>(tm), SecureRandom())
    ctx.socketFactory
}

/** Opens a msgpack POST connection to msfrpcd's /api/ endpoint (self-signed TLS accepted). */
internal fun openRpcConnection(
    host: String,
    port: Int,
    ssl: Boolean,
    readTimeoutMs: Int,
    contentLength: Int,
): HttpURLConnection {
    val scheme = if (ssl) "https" else "http"
    val url = URL("$scheme://$host:$port/api/")

    return (url.openConnection() as HttpURLConnection).apply {
        requestMethod = "POST"
        doOutput = true
        doInput = true
        connectTimeout = 10_000
        readTimeout = readTimeoutMs
        setRequestProperty("Content-Type", "binary/message-pack")
        setRequestProperty("Content-Length", contentLength.toString())

        if (this is HttpsURLConnection) {
            sslSocketFactory = trustAllSslFactory
            setHostnameVerifier { _, _ -> true }
        }
    }
}

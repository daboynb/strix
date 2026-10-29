package org.csploit.strix.data.bundle

import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL

private const val MAX_REDIRECTS = 5
private const val USER_AGENT = "strix-bundle-updater"

/**
 * Open [url] following up to [MAX_REDIRECTS] redirects, re-sending [headers] on
 * every hop; with [requireHttps] every hop must be https (no downgrades).
 */
internal fun openFollowingRedirects(
    url: String,
    headers: Map<String, String>,
    requireHttps: Boolean,
    connectTimeoutMs: Int,
    readTimeoutMs: Int,
): HttpURLConnection {
    var current = URL(url)
    repeat(MAX_REDIRECTS + 1) {
        if (requireHttps && current.protocol != "https") throw IOException("refusing non-https URL $current")
        val conn = (current.openConnection() as HttpURLConnection).apply {
            instanceFollowRedirects = false
            connectTimeout = connectTimeoutMs
            readTimeout = readTimeoutMs
            setRequestProperty("User-Agent", USER_AGENT)
            headers.forEach { (k, v) -> setRequestProperty(k, v) }
        }
        val code = conn.responseCode
        if (code !in 300..399 || code == 304) return conn
        val location = conn.getHeaderField("Location") ?: throw IOException("redirect without Location")
        conn.disconnect()
        current = URL(current, location)
    }
    throw IOException("too many redirects for $url")
}

internal fun readCapped(input: InputStream, max: Int): ByteArray {
    val out = java.io.ByteArrayOutputStream()
    val buf = ByteArray(8192)
    while (true) {
        val n = input.read(buf)
        if (n < 0) break
        if (out.size() + n > max) throw IOException("response larger than $max bytes")
        out.write(buf, 0, n)
    }
    return out.toByteArray()
}

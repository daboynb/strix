package org.csploit.strix.data.bundle

import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * Minimal HTTP client for bundle downloads: explicit timeouts, manual redirect
 * handling (GitHub asset URLs redirect to objects.githubusercontent.com; we
 * re-send the Range header on every hop and refuse https→http downgrades),
 * and Range resume into `<dest>.part`.
 *
 * [requireHttps] is false only in tests against a local server.
 */
class BundleDownloader(
    private val requireHttps: Boolean = true,
    private val connectTimeoutMs: Int = 15_000,
    private val readTimeoutMs: Int = 30_000,
) {
    companion object {
        private const val MAX_REDIRECTS = 5
        private const val USER_AGENT = "strix-bundle-updater"
    }

    /** GET a small resource fully into memory (API responses, manifests, signatures). */
    fun fetchBytes(url: String, maxBytes: Int, accept: String? = null): ByteArray {
        val conn = open(url, buildMap { accept?.let { put("Accept", it) } })
        try {
            if (conn.responseCode != 200) throw IOException("HTTP ${conn.responseCode} for $url")
            return conn.inputStream.use { readCapped(it, maxBytes) }
        } finally {
            conn.disconnect()
        }
    }

    /**
     * Download [url] to [dest], resuming `<dest>.part` with a Range request.
     * Verifies [expectedSize] and [expectedSha256]; a hash mismatch deletes the
     * partial file. Cancellation is checked between reads; the partial file
     * is kept so the next attempt resumes.
     */
    suspend fun download(
        url: String,
        dest: File,
        expectedSize: Long,
        expectedSha256: String,
        onProgress: (Long, Long) -> Unit = { _, _ -> },
    ): File {
        dest.parentFile?.mkdirs()
        val part = File(dest.path + ".part")
        if (part.length() > expectedSize) part.delete()
        var restarted = false
        while (part.length() < expectedSize) {
            currentCoroutineContext().ensureActive()
            val offset = part.length()
            val conn = open(url, if (offset > 0) mapOf("Range" to "bytes=$offset-") else emptyMap())
            try {
                val append = when (val code = conn.responseCode) {
                    206 -> {
                        val start = conn.getHeaderField("Content-Range")?.let(::parseRangeStart)
                        if (start != offset) throw IOException("server resumed at $start, expected $offset")
                        true
                    }
                    200 -> false // server ignored Range: start over
                    416 -> {
                        if (restarted) throw IOException("HTTP 416 for $url")
                        restarted = true
                        part.delete()
                        continue
                    }
                    else -> throw IOException("HTTP $code for $url")
                }
                conn.inputStream.use { input ->
                    FileOutputStream(part, append).use { out ->
                        val buf = ByteArray(65536)
                        var written = if (append) offset else 0L
                        while (true) {
                            currentCoroutineContext().ensureActive()
                            val n = input.read(buf)
                            if (n < 0) break
                            if (written + n > expectedSize) throw IOException("server sent more than $expectedSize bytes")
                            out.write(buf, 0, n)
                            written += n
                            onProgress(written, expectedSize)
                        }
                    }
                }
                if (part.length() < expectedSize) throw IOException("connection closed at ${part.length()}/$expectedSize")
            } finally {
                conn.disconnect()
            }
        }
        onProgress(part.length(), expectedSize)
        val actual = sha256(part)
        if (actual != expectedSha256.lowercase()) {
            part.delete()
            throw IOException("sha256 mismatch (got $actual), download discarded")
        }
        dest.delete()
        if (!part.renameTo(dest)) throw IOException("cannot rename ${part.name}")
        return dest
    }

    /** Open [url] following up to [MAX_REDIRECTS] redirects, re-sending [headers] on every hop. */
    internal fun open(url: String, headers: Map<String, String>): HttpURLConnection {
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

    private fun parseRangeStart(header: String): Long? =
        Regex("bytes (\\d+)-").find(header)?.groupValues?.get(1)?.toLongOrNull()

    private fun readCapped(input: InputStream, max: Int): ByteArray {
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
}

fun sha256(file: File): String {
    val md = MessageDigest.getInstance("SHA-256")
    file.inputStream().use { input ->
        val buf = ByteArray(65536)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            md.update(buf, 0, n)
        }
    }
    return md.digest().toHex()
}

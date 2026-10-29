package org.csploit.strix.data.bundle

import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException
import java.util.Collections
import kotlin.random.Random

class BundleDownloaderTest {
    @get:Rule val tmp = TemporaryFolder()

    private val payload = Random(42).nextBytes(300_000)
    private val sha = TarFixture.sha256(payload)
    private val ranges: MutableList<String?> = Collections.synchronizedList(mutableListOf())
    private var honourRange = true
    private val server: TinyHttpServer = TinyHttpServer { path, headers, resp ->
        when (path) {
            "/file" -> {
                val range = headers["range"]
                ranges += range
                val start = range?.removePrefix("bytes=")?.removeSuffix("-")?.toInt()
                if (start != null && honourRange) {
                    resp.send(206, mapOf("Content-Range" to "bytes $start-${payload.size - 1}/${payload.size}"), payload, start)
                } else {
                    resp.send(200, body = payload)
                }
            }
            // Cross-host redirect (127.0.0.1 -> localhost), like github.com -> objects.githubusercontent.com
            "/redirect" -> resp.send(302, mapOf("Location" to "http://localhost:$port/file"))
            else -> resp.send(404)
        }
    }
    private val port: Int get() = server.port
    private val base = "http://127.0.0.1:${server.port}"
    private val downloader = BundleDownloader(requireHttps = false)

    @After fun stop() = server.stop()

    private fun partialPart(dest: File, bytes: Int) =
        File(dest.path + ".part").apply { writeBytes(payload.copyOf(bytes)) }

    @Test fun fullDownload() = runBlocking {
        val dest = File(tmp.root, "dl/bundle.bin")
        var last = 0L
        downloader.download("$base/file", dest, payload.size.toLong(), sha) { done, _ -> last = done }
        assertArrayEquals(payload, dest.readBytes())
        assertEquals(payload.size.toLong(), last)
        assertFalse(File(dest.path + ".part").exists())
        assertEquals(listOf<String?>(null), ranges.toList())
    }

    @Test fun resumesWithRange() = runBlocking {
        val dest = File(tmp.root, "bundle.bin")
        partialPart(dest, 123_456)
        downloader.download("$base/file", dest, payload.size.toLong(), sha)
        assertArrayEquals(payload, dest.readBytes())
        assertEquals(listOf<String?>("bytes=123456-"), ranges.toList())
    }

    @Test fun restartsWhenServerIgnoresRange() = runBlocking {
        honourRange = false
        val dest = File(tmp.root, "bundle.bin")
        partialPart(dest, 1000)
        downloader.download("$base/file", dest, payload.size.toLong(), sha)
        assertArrayEquals(payload, dest.readBytes())
    }

    @Test fun followsCrossHostRedirectKeepingRange() = runBlocking {
        val dest = File(tmp.root, "bundle.bin")
        partialPart(dest, 5000)
        downloader.download("$base/redirect", dest, payload.size.toLong(), sha)
        assertArrayEquals(payload, dest.readBytes())
        assertEquals("Range survives the redirect hop", listOf<String?>("bytes=5000-"), ranges.toList())
    }

    @Test fun hashMismatchDeletesPartial() = runBlocking {
        val dest = File(tmp.root, "bundle.bin")
        val r = runCatching { downloader.download("$base/file", dest, payload.size.toLong(), "0".repeat(64)) }
        assertTrue(r.exceptionOrNull() is IOException)
        assertFalse(dest.exists())
        assertFalse(File(dest.path + ".part").exists())
    }

    @Test fun corruptPartialIsDetected() = runBlocking {
        val dest = File(tmp.root, "bundle.bin")
        File(dest.path + ".part").writeBytes(ByteArray(1000)) // wrong bytes, resumed after them
        val r = runCatching { downloader.download("$base/file", dest, payload.size.toLong(), sha) }
        assertTrue(r.exceptionOrNull()!!.message!!.contains("sha256"))
        assertFalse(File(dest.path + ".part").exists())
    }

    @Test fun httpsRequiredByDefault() {
        val r = runCatching { BundleDownloader().fetchBytes("$base/file", 1_000_000) }
        assertTrue(r.exceptionOrNull()!!.message!!.contains("non-https"))
    }

    @Test fun fetchBytesIsCapped() {
        val r = runCatching { downloader.fetchBytes("$base/file", 1000) }
        assertTrue(r.exceptionOrNull() is IOException)
    }
}

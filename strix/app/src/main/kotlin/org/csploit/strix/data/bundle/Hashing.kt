package org.csploit.strix.data.bundle

import java.io.File
import java.io.FilterInputStream
import java.io.InputStream
import java.security.MessageDigest

/** Counts and SHA-256-hashes every byte read; skip() reads so nothing bypasses the hash. */
internal class HashingStream(input: InputStream) : FilterInputStream(input) {
    private val digest = MessageDigest.getInstance("SHA-256")
    var count = 0L
        private set

    override fun read(): Int = super.read().also {
        if (it >= 0) { digest.update(it.toByte()); count++ }
    }
    override fun read(b: ByteArray, off: Int, len: Int): Int = super.read(b, off, len).also {
        if (it > 0) { digest.update(b, off, it); count += it }
    }
    override fun skip(n: Long): Long {
        val buf = ByteArray(minOf(n, 65536L).toInt().coerceAtLeast(1))
        var left = n
        while (left > 0) {
            val r = read(buf, 0, minOf(left, buf.size.toLong()).toInt())
            if (r < 0) break
            left -= r
        }
        return n - left
    }
    override fun markSupported() = false
    fun hexDigest(): String = digest.digest().toHex()
}

internal class NonClosing(input: InputStream) : FilterInputStream(input) {
    override fun close() {}
}

internal fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

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

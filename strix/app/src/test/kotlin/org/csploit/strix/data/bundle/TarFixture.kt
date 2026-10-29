package org.csploit.strix.data.bundle

import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream
import org.apache.commons.compress.archivers.tar.TarConstants
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.zip.GZIPOutputStream

/** Builds small .tar.gz archives in memory for extractor/installer tests. */
class TarFixture {
    private sealed class E {
        data class F(val name: String, val data: ByteArray, val mode: Int) : E()
        data class D(val name: String) : E()
        data class L(val name: String, val target: String, val hard: Boolean) : E()
    }

    private val entries = mutableListOf<E>()

    fun file(name: String, content: String = name, mode: Int = 0b110_100_100) = apply {
        entries += E.F(name, content.toByteArray(), mode)
    }
    fun dir(name: String) = apply { entries += E.D(name) }
    fun symlink(name: String, target: String) = apply { entries += E.L(name, target, false) }
    fun hardlink(name: String, target: String) = apply { entries += E.L(name, target, true) }

    fun build(): ByteArray {
        val bytes = ByteArrayOutputStream()
        TarArchiveOutputStream(GZIPOutputStream(bytes)).use { tar ->
            tar.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX)
            for (e in entries) when (e) {
                is E.F -> {
                    val te = TarArchiveEntry(e.name, true).apply { size = e.data.size.toLong(); mode = e.mode or 0x8000 }
                    tar.putArchiveEntry(te); tar.write(e.data); tar.closeArchiveEntry()
                }
                is E.D -> { tar.putArchiveEntry(TarArchiveEntry(e.name + "/", true)); tar.closeArchiveEntry() }
                is E.L -> {
                    val type = if (e.hard) TarConstants.LF_LINK else TarConstants.LF_SYMLINK
                    val te = TarArchiveEntry(e.name, type, true).apply { linkName = e.target }
                    tar.putArchiveEntry(te); tar.closeArchiveEntry()
                }
            }
        }
        return bytes.toByteArray()
    }

    companion object {
        fun sha256(b: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

        fun manifestJson(id: String, archive: ByteArray, version: String = "1.0", minApp: Int = 1, unpacked: Long = 1024) =
            """{"format":1,"id":"$id","version":"$version","file":"$id-bundle.tar.gz.bin","sha256":"${sha256(archive)}","size":${archive.size},"unpacked":$unpacked,"minApp":$minApp}"""
    }
}

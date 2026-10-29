package org.csploit.strix.data.bundle

import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import java.io.BufferedInputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.nio.file.Files
import java.util.zip.GZIPInputStream
import kotlin.coroutines.cancellation.CancellationException

/**
 * Extracts a .tar.gz into [root], refusing anything that would land outside it:
 * absolute names, `..` components, symlinks (or hardlinks) whose target
 * escapes [root], and writes through a previously created symlink.
 */
object SafeTarExtractor {

    class UnsafeEntryException(message: String) : IOException(message)

    /**
     * [mapPath] maps an archive name (already stripped of a leading "./") to a
     * path relative to [root], or null to skip the entry. [onEntry] receives the
     * running file count and the mapped name; it may throw [CancellationException].
     * Returns the number of non-directory entries extracted.
     */
    fun extract(
        gzStream: InputStream,
        root: File,
        mapPath: (String) -> String? = { it },
        onEntry: (Int, String) -> Unit = { _, _ -> },
    ): Int {
        root.mkdirs()
        val rootReal = root.toPath().toRealPath()
        var count = 0
        val buffer = ByteArray(65536)
        TarArchiveInputStream(GZIPInputStream(BufferedInputStream(gzStream, 65536))).use { tar ->
            var entry: TarArchiveEntry? = tar.nextEntry
            while (entry != null) {
                val raw = entry.name.removePrefix("./")
                val mapped = if (raw.isEmpty()) null else mapPath(raw)
                if (mapped != null) {
                    val rel = checkRelative(mapped)
                    val out = rootReal.resolve(rel).normalize()
                    if (!out.startsWith(rootReal) || out == rootReal) throw UnsafeEntryException("entry escapes root: ${entry.name}")
                    when {
                        entry.isDirectory -> {
                            TarGuards.ensureParentInside(out, rootReal, entry.name)
                            Files.createDirectories(out)
                            TarGuards.ensureRealInside(out, rootReal, entry.name)
                            out.toFile().apply { setReadable(true, false); setExecutable(true, false) }
                        }
                        entry.isSymbolicLink -> {
                            TarGuards.createSymlink(out, entry.linkName, rootReal, entry.name)
                            count++
                        }
                        entry.isLink -> {
                            TarGuards.copyHardlink(out, entry.linkName, rootReal, mapPath, entry.name)
                            count++
                        }
                        entry.isFile -> {
                            TarGuards.prepareTarget(out, rootReal, entry.name)
                            out.toFile().outputStream().use { dst ->
                                var len = tar.read(buffer)
                                while (len > 0) {
                                    dst.write(buffer, 0, len)
                                    len = tar.read(buffer)
                                }
                            }
                            applyMode(out.toFile(), entry.mode)
                            count++
                            onEntry(count, mapped)
                        }
                        // Device nodes, fifos etc. have no business in a bundle.
                        else -> {}
                    }
                }
                entry = tar.nextEntry
            }
        }
        TarGuards.verifySymlinks(rootReal)
        return count
    }

    /** Reject absolute paths and any `..` component; returns the cleaned relative path. */
    internal fun checkRelative(name: String): String {
        if (name.startsWith("/") || name.startsWith("\\")) throw UnsafeEntryException("absolute path: $name")
        val parts = name.split('/').filter { it.isNotEmpty() && it != "." }
        if (parts.isEmpty()) throw UnsafeEntryException("empty path: $name")
        if (parts.any { it == ".." }) throw UnsafeEntryException("parent traversal: $name")
        return parts.joinToString("/")
    }

    private fun applyMode(f: File, mode: Int) {
        f.setReadable(true, false)
        if (mode and 0b001_001_001 != 0) f.setExecutable(true, false)
    }
}

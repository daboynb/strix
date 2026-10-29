package org.csploit.strix.data.bundle

import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import java.io.BufferedInputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.Paths
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
                            ensureParentInside(out, rootReal, entry.name)
                            Files.createDirectories(out)
                            ensureRealInside(out, rootReal, entry.name)
                            out.toFile().apply { setReadable(true, false); setExecutable(true, false) }
                        }
                        entry.isSymbolicLink -> {
                            createSymlink(out, entry.linkName, rootReal, entry.name)
                            count++
                        }
                        entry.isLink -> {
                            copyHardlink(out, entry.linkName, rootReal, mapPath, entry.name)
                            count++
                        }
                        entry.isFile -> {
                            prepareTarget(out, rootReal, entry.name)
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
        verifySymlinks(rootReal)
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

    private fun prepareTarget(out: Path, rootReal: Path, name: String) {
        ensureParentInside(out, rootReal, name)
        if (Files.isSymbolicLink(out) || Files.isRegularFile(out, LinkOption.NOFOLLOW_LINKS)) Files.delete(out)
        else if (Files.isDirectory(out, LinkOption.NOFOLLOW_LINKS)) throw UnsafeEntryException("file over directory: $name")
    }

    /** Create the parent and make sure its *real* path (symlinks resolved) is inside root. */
    private fun ensureParentInside(out: Path, rootReal: Path, name: String) {
        val parent = out.parent
        // Check the nearest existing ancestor *before* creating anything, so a
        // symlink that started resolving outside can't make us mkdir out there.
        var existing: Path = parent
        while (!Files.exists(existing)) existing = existing.parent ?: break
        ensureRealInside(existing, rootReal, name)
        Files.createDirectories(parent)
        ensureRealInside(parent, rootReal, name)
    }

    private fun ensureRealInside(p: Path, rootReal: Path, name: String) {
        if (!p.toRealPath().startsWith(rootReal)) throw UnsafeEntryException("path resolves outside root: $name")
    }

    private fun createSymlink(out: Path, target: String, rootReal: Path, name: String) {
        if (target.isEmpty() || target.startsWith("/")) throw UnsafeEntryException("absolute or empty symlink target: $name -> $target")
        val lexical = out.parent.resolve(target).normalize()
        if (!lexical.startsWith(rootReal)) throw UnsafeEntryException("symlink escapes root: $name -> $target")
        prepareTarget(out, rootReal, name)
        Files.createSymbolicLink(out, Paths.get(target))
        checkLinkResolution(out, rootReal, name)
    }

    /** Hardlink names are archive-root relative: copy the (already extracted) target. */
    private fun copyHardlink(out: Path, target: String, rootReal: Path, mapPath: (String) -> String?, name: String) {
        val mappedTarget = mapPath(target.removePrefix("./")) ?: throw UnsafeEntryException("hardlink target skipped: $name -> $target")
        val src = rootReal.resolve(checkRelative(mappedTarget)).normalize()
        if (!src.startsWith(rootReal) || !Files.isRegularFile(src)) throw UnsafeEntryException("bad hardlink target: $name -> $target")
        ensureRealInside(src, rootReal, name)
        prepareTarget(out, rootReal, name)
        Files.copy(src, out)
        out.toFile().setReadable(true, false)
        out.toFile().setExecutable(src.toFile().canExecute(), false)
    }

    /** A symlink whose target exists must really resolve inside root (catches `a -> .` + `b -> a/..` tricks). */
    private fun checkLinkResolution(link: Path, rootReal: Path, name: String) {
        if (!Files.exists(link)) return // dangling: harmless until something exists there
        if (!link.toRealPath().startsWith(rootReal)) {
            Files.deleteIfExists(link)
            throw UnsafeEntryException("symlink resolves outside root: $name")
        }
    }

    /** Final pass: links dangling at creation may resolve now that every entry exists. */
    private fun verifySymlinks(rootReal: Path) {
        Files.walk(rootReal).use { paths ->
            paths.filter { Files.isSymbolicLink(it) }.forEach { checkLinkResolution(it, rootReal, rootReal.relativize(it).toString()) }
        }
    }

    private fun applyMode(f: File, mode: Int) {
        f.setReadable(true, false)
        if (mode and 0b001_001_001 != 0) f.setExecutable(true, false)
    }
}

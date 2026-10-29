package org.csploit.strix.data.bundle

import org.csploit.strix.data.bundle.SafeTarExtractor.UnsafeEntryException
import org.csploit.strix.data.bundle.SafeTarExtractor.checkRelative
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.Paths

/**
 * Containment checks and link handling for [SafeTarExtractor]: every target
 * path, symlink and hardlink must really resolve inside the extraction root.
 */
internal object TarGuards {

    fun prepareTarget(out: Path, rootReal: Path, name: String) {
        ensureParentInside(out, rootReal, name)
        if (Files.isSymbolicLink(out) || Files.isRegularFile(out, LinkOption.NOFOLLOW_LINKS)) Files.delete(out)
        else if (Files.isDirectory(out, LinkOption.NOFOLLOW_LINKS)) throw UnsafeEntryException("file over directory: $name")
    }

    /** Create the parent and make sure its *real* path (symlinks resolved) is inside root. */
    fun ensureParentInside(out: Path, rootReal: Path, name: String) {
        val parent = out.parent
        // Check the nearest existing ancestor *before* creating anything, so a
        // symlink that started resolving outside can't make us mkdir out there.
        var existing: Path = parent
        while (!Files.exists(existing)) existing = existing.parent ?: break
        ensureRealInside(existing, rootReal, name)
        Files.createDirectories(parent)
        ensureRealInside(parent, rootReal, name)
    }

    fun ensureRealInside(p: Path, rootReal: Path, name: String) {
        if (!p.toRealPath().startsWith(rootReal)) throw UnsafeEntryException("path resolves outside root: $name")
    }

    fun createSymlink(out: Path, target: String, rootReal: Path, name: String) {
        if (target.isEmpty() || target.startsWith("/")) throw UnsafeEntryException("absolute or empty symlink target: $name -> $target")
        val lexical = out.parent.resolve(target).normalize()
        if (!lexical.startsWith(rootReal)) throw UnsafeEntryException("symlink escapes root: $name -> $target")
        prepareTarget(out, rootReal, name)
        Files.createSymbolicLink(out, Paths.get(target))
        checkLinkResolution(out, rootReal, name)
    }

    /** Hardlink names are archive-root relative: copy the (already extracted) target. */
    fun copyHardlink(out: Path, target: String, rootReal: Path, mapPath: (String) -> String?, name: String) {
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
    fun verifySymlinks(rootReal: Path) {
        Files.walk(rootReal).use { paths ->
            paths.filter { Files.isSymbolicLink(it) }.forEach { checkLinkResolution(it, rootReal, rootReal.relativize(it).toString()) }
        }
    }
}

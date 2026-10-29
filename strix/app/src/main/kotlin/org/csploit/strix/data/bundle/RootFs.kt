package org.csploit.strix.data.bundle

import org.csploit.strix.core.Logger
import org.csploit.strix.core.shellQuote
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.util.concurrent.TimeUnit

/**
 * File operations that may hit root-owned files (msfrpcd runs as root and
 * leaves root-owned data behind). Tries as the app uid first, then `su`.
 */
open class RootFs {

    /** Run [command] via `su -c`; true on exit code 0. Blocking. */
    open fun su(command: String, timeoutSec: Long = 300): Boolean = try {
        val p = ProcessBuilder("su", "-c", command).redirectErrorStream(true).start()
        p.inputStream.bufferedReader().readText()
        p.waitFor(timeoutSec, TimeUnit.SECONDS) && p.exitValue() == 0
    } catch (e: Exception) {
        Logger.warning("RootFs: su failed for '$command': ${e.message}")
        false
    }

    /** Delete [f] recursively (never following symlinks); true if it is gone afterwards. */
    fun deleteTree(f: File): Boolean {
        if (!exists(f)) return true
        deleteNoFollow(f)
        if (!exists(f)) return true
        su("rm -rf ${shellQuote(f.absolutePath)}")
        return !exists(f)
    }

    /** Rename [from] to [to] (same filesystem); falls back to `su mv`. */
    fun move(from: File, to: File): Boolean {
        if (from.renameTo(to)) return true
        return su("mv ${shellQuote(from.absolutePath)} ${shellQuote(to.absolutePath)}") && exists(to)
    }

    fun exists(f: File): Boolean = f.exists() || Files.isSymbolicLink(f.toPath())

    /** Best-effort delete as the app uid; symlinks are removed, never followed. */
    private fun deleteNoFollow(f: File) {
        val p = f.toPath()
        if (Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS)) {
            try {
                Files.newDirectoryStream(p).use { children -> children.forEach { deleteNoFollow(it.toFile()) } }
            } catch (_: Exception) {
                // Unreadable (root-owned) directory: leave it for su.
            }
        }
        try { Files.deleteIfExists(p) } catch (_: Exception) {}
    }
}

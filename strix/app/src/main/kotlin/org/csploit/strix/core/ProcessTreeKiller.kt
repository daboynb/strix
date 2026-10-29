package org.csploit.strix.core

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeoutOrNull

private const val PID_WAIT_MS = 2_000L
private const val TERM_GRACE_SECONDS = 1

/**
 * Destroying [process] alone only kills the su/sh wrapper (and with su the
 * root shell is not even its child), leaving the real tool running as root.
 * Instead snapshot the wrapper shell's descendants, TERM them all, wait a
 * short grace period, then KILL whatever is left — through the same su/sh.
 */
internal suspend fun killTree(process: Process, shellPid: CompletableDeferred<Int>, asSu: Boolean) {
    val pid = withTimeoutOrNull(PID_WAIT_MS) { shellPid.await() }
    if (pid != null) {
        // The list is collected once: after TERM the survivors are
        // reparented to init and no longer reachable via pgrep -P.
        val script = "t(){ echo \$1; for c in \$(pgrep -P \$1); do t \$c; done; }; " +
            "p=\$(t $pid); kill -TERM \$p 2>/dev/null; " +
            "sleep $TERM_GRACE_SECONDS; kill -KILL \$p 2>/dev/null; exit 0"
        try {
            val killer = (if (asSu) ProcessBuilder("su", "-c", script) else ProcessBuilder("sh", "-c", script))
                .redirectErrorStream(true)
                .start()
            killer.inputStream.use { it.readBytes() }
            killer.waitFor()
        } catch (e: Exception) {
            Logger.warning("ProcessManager: tree kill of pid=$pid failed: ${e.message}")
        }
    } else {
        Logger.warning("ProcessManager: wrapper pid unknown, destroying wrapper only")
    }
    process.destroyForcibly()
}

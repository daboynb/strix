package org.csploit.strix.core

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.concurrent.atomic.AtomicBoolean
import javax.inject.Inject
import javax.inject.Singleton

sealed class ProcessEvent {
    data class StdoutLine(val line: String) : ProcessEvent()
    data class StderrLine(val line: String) : ProcessEvent()
    data class Exited(val code: Int) : ProcessEvent()
    data class Killed(val signal: Int) : ProcessEvent()
}

/**
 * Quote [s] as a single POSIX shell word: wrap in single quotes and turn every
 * embedded `'` into `'\''`. Use for every user-controlled value that ends up in
 * a command passed to [ProcessManager.execute].
 */
fun shellQuote(s: String): String = "'" + s.replace("'", "'\\''") + "'"

/** Replace every non-blank secret in [text] with "***" (longest first, so overlapping secrets don't leak). */
internal fun redactSecrets(text: String, secrets: Collection<String>): String =
    secrets.filter { it.isNotBlank() }
        .sortedByDescending { it.length }
        .fold(text) { acc, secret -> acc.replace(secret, "***") }

/** Map a shell exit status: 129..159 means "terminated by signal (status-128)", anything else is a plain exit code. */
internal fun exitEventFor(exitValue: Int): ProcessEvent =
    if (exitValue in 129..(128 + 31)) ProcessEvent.Killed(exitValue - 128) else ProcessEvent.Exited(exitValue)

@Singleton
class ProcessManager @Inject constructor() {

    companion object {
        // First stdout line of every wrapper shell: its own PID, consumed here
        // (never emitted) so cancellation can kill the whole process tree.
        private const val PID_MARKER = "__STRIX_PID__"
        private val PID_LINE = Regex("""^${PID_MARKER}(\d+)$""")
        private const val PID_WAIT_MS = 2_000L
        private const val TERM_GRACE_SECONDS = 1
    }

    // Kill sequences outlive the cancelled flow (TERM, grace, KILL).
    private val killScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /**
     * Execute a command via su and emit output as a Flow.
     * The process tree is killed (TERM, then KILL) when the Flow collector is cancelled.
     * Every occurrence of [secrets] in logged command lines is replaced with "***".
     */
    fun execute(
        command: String,
        env: Map<String, String> = emptyMap(),
        toolsDir: String? = null,
        workDir: String? = null,
        asSu: Boolean = true,
        secrets: Collection<String> = emptyList(),
    ): Flow<ProcessEvent> = callbackFlow {
        val shellCmd = buildShellCommand(command, env, toolsDir, workDir)
        val logCmd = redactSecrets(command, secrets)

        val pb = if (asSu) {
            ProcessBuilder("su", "-c", shellCmd)
        } else {
            ProcessBuilder("sh", "-c", shellCmd)
        }
        pb.redirectErrorStream(false)

        val process = withContext(Dispatchers.IO) { pb.start() }
        val startedAt = System.currentTimeMillis()
        val shellPid = CompletableDeferred<Int>()
        val exited = AtomicBoolean(false)

        Logger.debug("ProcessManager: started cmd=$logCmd")

        val stdoutJob = launch(Dispatchers.IO) {
            try {
                BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
                    var line = reader.readLine()
                    while (line != null) {
                        val pid = if (!shellPid.isCompleted) PID_LINE.find(line)?.groupValues?.get(1)?.toIntOrNull() else null
                        if (pid != null) {
                            shellPid.complete(pid)
                        } else {
                            send(ProcessEvent.StdoutLine(line))
                        }
                        line = reader.readLine()
                    }
                }
            } catch (_: java.io.IOException) {
                // Stream closed or interrupted during cancellation
            }
        }

        val stderrJob = launch(Dispatchers.IO) {
            try {
                BufferedReader(InputStreamReader(process.errorStream)).use { reader ->
                    var line = reader.readLine()
                    while (line != null) {
                        send(ProcessEvent.StderrLine(line))
                        line = reader.readLine()
                    }
                }
            } catch (_: java.io.IOException) {
                // Stream closed or interrupted during cancellation
            }
        }

        launch(Dispatchers.IO) {
            stdoutJob.join()
            stderrJob.join()
            val exitValue = process.waitFor()
            exited.set(true)
            val elapsedMs = System.currentTimeMillis() - startedAt
            Logger.info("ProcessManager: exited cmd=$logCmd code=$exitValue after ${elapsedMs}ms")
            send(exitEventFor(exitValue))
            close()
        }

        awaitClose {
            if (exited.get()) return@awaitClose
            Logger.debug("ProcessManager: killing process tree for cmd=$logCmd")
            killScope.launch { killTree(process, shellPid, asSu) }
        }
    }

    /**
     * Destroying [process] alone only kills the su/sh wrapper (and with su the
     * root shell is not even its child), leaving the real tool running as root.
     * Instead snapshot the wrapper shell's descendants, TERM them all, wait a
     * short grace period, then KILL whatever is left — through the same su/sh.
     */
    private suspend fun killTree(process: Process, shellPid: CompletableDeferred<Int>, asSu: Boolean) {
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

    private fun buildShellCommand(
        command: String,
        env: Map<String, String>,
        toolsDir: String?,
        workDir: String?,
    ): String = buildString {
        val dollar = '$'
        append("echo ").append(PID_MARKER).append(dollar).append(dollar).append(" ; ")
        if (workDir != null) {
            append("cd ").append(shellQuote(workDir)).append(" ; ")
        }
        if (toolsDir != null) {
            val dir = toolsDir.trimEnd('/')
            append("export PATH=").append(shellQuote("$dir/bin")).append(":").append(dollar).append("PATH ; ")
            append("export NMAPDIR=").append(shellQuote("$dir/share/nmap")).append(" ; ")
        }
        for ((key, value) in env) {
            append("export ").append(key).append("=").append(shellQuote(value)).append(" ; ")
        }
        append(command)
    }
}

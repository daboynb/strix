package org.csploit.strix.core

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ProcessManagerSafetyTest {

    private val processManager = ProcessManager()

    /** True while [pid] exists and is not a zombie. */
    private fun isAlive(pid: Int): Boolean {
        val stat = File("/proc/$pid/stat")
        if (!stat.exists()) return false
        val text = try { stat.readText() } catch (_: Exception) { return false }
        // Format: "pid (comm) S ..." — the state follows the last ')'.
        val state = text.substringAfterLast(')').trim().firstOrNull()
        return state != 'Z' && state != 'X'
    }

    /**
     * The wrapper runs a compound command; the long-running tool is a
     * grandchild (inner sh exec'd into sleep). Cancelling the collector must
     * kill it too, not just the wrapper shell.
     */
    @Test
    fun cancellingCollectorKillsChildOfCompoundCommand() = runBlocking {
        val command = "cd /tmp ; sh -c 'echo \$\$; exec sleep 300' ; echo after"
        val pid = CompletableDeferred<Int>()
        val collector = launch(Dispatchers.IO) {
            processManager.execute(command = command, asSu = false).collect { event ->
                if (event is ProcessEvent.StdoutLine) pid.complete(event.line.trim().toInt())
            }
        }
        val sleepPid = withTimeout(10_000) { pid.await() }
        assertTrue("sleep child should be running before cancellation", isAlive(sleepPid))

        collector.cancelAndJoin()

        val deadline = System.currentTimeMillis() + 10_000
        while (isAlive(sleepPid) && System.currentTimeMillis() < deadline) delay(100)
        assertFalse("sleep child pid=$sleepPid survived collector cancellation", isAlive(sleepPid))
    }

    @Test
    fun pidMarkerIsNotEmitted() = runBlocking {
        val events = withTimeout(10_000) {
            processManager.execute(command = "echo hello", asSu = false).toList()
        }
        assertEquals(listOf(ProcessEvent.StdoutLine("hello"), ProcessEvent.Exited(0)), events)
    }

    @Test
    fun exit255IsAnExitCodeNotASignal() = runBlocking {
        val events = withTimeout(10_000) {
            processManager.execute(command = "exit 255", asSu = false).toList()
        }
        assertEquals(listOf(ProcessEvent.Exited(255)), events)
    }

    @Test
    fun childKilledBySignalIsReportedAsKilled() = runBlocking {
        val events = withTimeout(10_000) {
            processManager.execute(command = "sh -c 'kill -9 \$\$'", asSu = false).toList()
        }
        // The shell may print "Killed" on stderr; only the terminal event matters.
        assertEquals(ProcessEvent.Killed(9), events.last())
    }

    @Test
    fun exitStatusMapping() {
        assertEquals(ProcessEvent.Exited(128), exitEventFor(128))
        assertEquals(ProcessEvent.Killed(1), exitEventFor(129))
        assertEquals(ProcessEvent.Killed(15), exitEventFor(143))
        assertEquals(ProcessEvent.Killed(31), exitEventFor(159))
        assertEquals(ProcessEvent.Exited(160), exitEventFor(160))
        assertEquals(ProcessEvent.Exited(255), exitEventFor(255))
    }

    @Test
    fun secretsAreRedacted() {
        assertEquals(
            "msfrpcd -U msf -P *** -a 127.0.0.1",
            redactSecrets("msfrpcd -U msf -P s3cr3t -a 127.0.0.1", listOf("s3cr3t")),
        )
        // Blank secrets are ignored (replacing "" would mangle every character).
        assertEquals("abc", redactSecrets("abc", listOf("", " ")))
        // Longest first: a secret containing a shorter one is fully hidden.
        assertEquals("x *** y", redactSecrets("x passw0rd y", listOf("pass", "passw0rd")))
    }

    /** shellQuote must round-trip arbitrary text as exactly one shell word. */
    @Test
    fun shellQuoteRoundTripsMetacharacters() = runBlocking {
        val inputs = listOf(
            "host 10.0.0.1 and (port 80 or port 443)",
            "len > 100",
            "a & b ; c | d",
            "it's \"quoted\" \$HOME `id` \\ *",
            "/login.php:user=^USER^&pass=^PASS^:F=x",
            "",
        )
        for (input in inputs) {
            val events = withTimeout(10_000) {
                processManager.execute(command = "printf '[%s]\\n' ${shellQuote(input)}", asSu = false).toList()
            }
            assertEquals("input: $input", listOf(ProcessEvent.StdoutLine("[$input]"), ProcessEvent.Exited(0)), events)
        }
    }

    @Test
    fun workDirAndEnvValuesAreQuoted() = runBlocking {
        val dir = File(System.getProperty("java.io.tmpdir"), "strix it's dir").apply { mkdirs() }
        try {
            val events = withTimeout(10_000) {
                processManager.execute(
                    command = "pwd ; printf '%s\\n' \"\$V\"",
                    env = mapOf("V" to "a'b & c"),
                    workDir = dir.absolutePath,
                    asSu = false,
                ).toList()
            }
            assertEquals(
                listOf(
                    ProcessEvent.StdoutLine(dir.canonicalPath),
                    ProcessEvent.StdoutLine("a'b & c"),
                    ProcessEvent.Exited(0),
                ),
                events,
            )
        } finally {
            dir.delete()
        }
    }
}

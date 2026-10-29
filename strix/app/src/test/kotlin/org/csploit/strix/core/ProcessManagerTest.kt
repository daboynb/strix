package org.csploit.strix.core

import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ProcessManagerTest {

    private val processManager = ProcessManager()

    /**
     * A process that prints a burst of lines faster than the collector drains
     * them (like nmap flushing a host group at the end of a scan) must still
     * deliver every line and the final Exited event. NetworkScanner only emits
     * ScanEnded on Exited/Killed, so a lost terminal event leaves the host list
     * spinner running forever.
     */
    @Test
    fun burstOutputWithSlowCollectorDeliversAllLinesAndExit() = runBlocking {
        val lineCount = 500

        val events = withTimeout(60_000) {
            processManager.execute(command = "seq 1 $lineCount", asSu = false)
                .onEach { delay(5) }
                .toList()
        }

        assertTrue(
            "last event must be Exited(0), was ${events.lastOrNull()}",
            events.lastOrNull() == ProcessEvent.Exited(0),
        )
        val stdout = events.filterIsInstance<ProcessEvent.StdoutLine>()
        assertEquals("stdout lines delivered", lineCount, stdout.size)
    }

    @Test
    fun nonZeroExitCodeIsReported() = runBlocking {
        val events = withTimeout(10_000) {
            processManager.execute(command = "exit 3", asSu = false).toList()
        }

        assertEquals(listOf(ProcessEvent.Exited(3)), events)
    }
}

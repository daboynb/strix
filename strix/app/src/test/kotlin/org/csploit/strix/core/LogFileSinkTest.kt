package org.csploit.strix.core

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

class LogFileSinkTest {
    private val dir: File = Files.createTempDirectory("strix-log").toFile()
    private var sink: LogFileSink? = null

    @After
    fun tearDown() {
        sink?.close()
        dir.deleteRecursively()
    }

    @Test
    fun rotatesAtMaxBytesKeepingOneBackup() {
        val s = LogFileSink(dir, maxBytes = 1_000).also { sink = it }
        repeat(100) { s.append("line %03d %s\n".format(it, "x".repeat(40))) }
        s.flush()
        assertTrue(s.current.length() <= 1_000)
        assertTrue(s.rotated.exists())
        assertTrue(s.rotated.length() <= 1_000)
        assertEquals(setOf("strix.log", "strix.log.1"), dir.list()!!.toSet())
        val all = s.readAll().lines().filter { it.isNotEmpty() }
        // Newest lines survive in order, oldest were rotated away.
        assertEquals("line 099 " + "x".repeat(40), all.last())
        assertFalse(all.any { it.startsWith("line 000 ") })
        val numbers = all.map { it.substring(5, 8).toInt() }
        assertEquals(numbers.sorted(), numbers)
    }

    @Test
    fun appendDoesNotBlockWhileWriterIsBusy() {
        val s = LogFileSink(dir).also { sink = it }
        val start = System.nanoTime()
        // Holding the lock stalls the writer thread (as slow disk IO would).
        synchronized(s.lock) {
            repeat(5_000) { s.append("line $it\n") }
            assertTrue("append blocked", System.nanoTime() - start < 1_000_000_000L)
            assertFalse(s.current.exists() && s.current.length() > 0)
        }
        s.flush()
        assertEquals(5_000, s.readAll().lines().count { it.startsWith("line ") })
    }

    @Test
    fun backgroundWriterEventuallyWritesWithoutFlush() {
        var notified = 0
        val s = LogFileSink(dir, onWritten = { notified++ }).also { sink = it }
        s.append("hello\n")
        val deadline = System.currentTimeMillis() + 5_000
        while (s.current.length() == 0L && System.currentTimeMillis() < deadline) Thread.sleep(10)
        assertEquals("hello\n", s.current.readText())
        assertTrue(notified > 0)
    }

    @Test
    fun writeSyncKeepsOrderAndClearDeletesFiles() {
        val s = LogFileSink(dir).also { sink = it }
        s.append("a\n")
        s.writeSync("crash\n")
        assertEquals("a\ncrash\n", s.current.readText())
        s.clear()
        assertFalse(s.current.exists())
        assertEquals("", s.readAll())
        s.append("b\n")
        assertEquals("b\n", s.readAll())
    }

    @Test
    fun fullQueueDropsAndReportsCount() {
        val s = LogFileSink(dir, queueCapacity = 10).also { sink = it }
        synchronized(s.lock) { repeat(15) { s.append("l$it\n") } }
        val text = s.readAll()
        assertTrue(text.contains("l9\n"))
        assertTrue(text.contains("log lines dropped"))
    }
}

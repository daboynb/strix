package org.csploit.strix.core

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

class LoggerTest {
    private val dir = Files.createTempDirectory("strix-logger").toFile()

    @After
    fun tearDown() {
        Logger.detach()
        dir.deleteRecursively()
    }

    @Test
    fun worksWithoutInit() {
        Logger.detach()
        Logger.debug("d")
        Logger.info("i")
        Logger.warning("w")
        Logger.error("e")
        Logger.error("e", RuntimeException("x"))
        Logger.crash(Thread.currentThread(), RuntimeException("y"))
        Logger.flush()
        assertEquals("", Logger.readLog())
        Logger.clearLog()
    }

    @Test
    fun writesFormattedLinesWithCallerTagAfterInit() {
        Logger.init(dir)
        Logger.info("hello file")
        Logger.error("failed", IllegalArgumentException("nope"))
        Logger.crash(Thread.currentThread(), IllegalStateException("dead"))
        val entries = LogFormat.parse(Logger.readLog())
        assertEquals(3, entries.size)
        assertEquals(LogLevel.INFO, entries[0].level)
        assertEquals("STRIX[core.LoggerTest.writesFormattedLinesWithCallerTagAfterInit]", entries[0].tag)
        assertEquals("hello file", entries[0].message)
        assertTrue(entries[1].message.contains("java.lang.IllegalArgumentException: nope"))
        assertEquals("STRIX[crash]", entries[2].tag)
        assertTrue(entries[2].message.startsWith("Uncaught exception in thread \"${Thread.currentThread().name}\""))
        assertTrue(entries[2].message.contains("IllegalStateException: dead"))
        assertTrue(dir.resolve(LogFileSink.FILE_NAME).exists())
    }
}

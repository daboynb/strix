package org.csploit.strix.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LogFormatTest {

    private fun line(level: LogLevel, msg: String, t: Throwable? = null) =
        LogFormat.format(1_700_000_000_000, level, "STRIX[data.X.y]", msg, t)

    @Test
    fun formatThenParseRoundTrips() {
        val text = line(LogLevel.INFO, "hello") + line(LogLevel.WARN, "careful: a: b")
        val entries = LogFormat.parse(text)
        assertEquals(2, entries.size)
        assertEquals(LogLevel.INFO, entries[0].level)
        assertEquals("STRIX[data.X.y]", entries[0].tag)
        assertEquals("hello", entries[0].message)
        assertEquals("careful: a: b", entries[1].message)
        assertTrue(entries[0].timestamp.matches(Regex("""\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}""")))
        assertEquals(text.trimEnd('\n'), entries.joinToString("\n") { it.toText() })
    }

    @Test
    fun stackTraceAndMultilineBecomeContinuationOfOneEntry() {
        val text = line(LogLevel.ERROR, "boom", IllegalStateException("bad")) +
            line(LogLevel.DEBUG, "first\nsecond") + line(LogLevel.INFO, "after")
        val entries = LogFormat.parse(text)
        assertEquals(3, entries.size)
        assertTrue(entries[0].message.startsWith("boom\njava.lang.IllegalStateException: bad"))
        assertTrue(entries[0].message.contains("\tat org.csploit.strix.core.LogFormatTest"))
        assertEquals("first\nsecond", entries[1].message)
        assertEquals("after", entries[2].message)
    }

    @Test
    fun orphanLinesBeforeFirstHeaderAreKept() {
        val entries = LogFormat.parse("garbage\n" + line(LogLevel.INFO, "ok"))
        assertEquals(listOf("garbage", "ok"), entries.map { it.message })
    }

    @Test
    fun levelFilterAndSearch() {
        val entries = LogFormat.parse(
            line(LogLevel.DEBUG, "d nmap") + line(LogLevel.INFO, "i") +
                line(LogLevel.WARN, "w NMAP") + line(LogLevel.ERROR, "e"),
        )
        assertEquals(4, LogFormat.filter(entries, LogLevel.DEBUG, "").size)
        assertEquals(listOf("i", "w NMAP", "e"), LogFormat.filter(entries, LogLevel.INFO, "").map { it.message })
        assertEquals(listOf("w NMAP", "e"), LogFormat.filter(entries, LogLevel.WARN, " ").map { it.message })
        assertEquals(listOf("e"), LogFormat.filter(entries, LogLevel.ERROR, "").map { it.message })
        assertEquals(listOf("d nmap", "w NMAP"), LogFormat.filter(entries, LogLevel.DEBUG, "nmap").map { it.message })
        assertEquals(4, LogFormat.filter(entries, LogLevel.DEBUG, "data.x").size)
    }

    @Test
    fun redactsSsidAndBssidButKeepsMacs() {
        val text = "detected network NetworkInfo(ssid=MyHome WiFi, bssid=aa:bb:cc:dd:ee:ff, localIp=192.168.1.5)\n" +
            "Startup complete: ssid=Cafe, ip=10.0.0.2\n" +
            "quoted ssid=\"a,b)c\" end\n" +
            "host 192.168.1.7 mac=11:22:33:44:55:66\n" +
            "SSID=Upper\n"
        val out = LogFormat.redact(text)
        assertFalse(out.contains("MyHome"))
        assertFalse(out.contains("aa:bb:cc:dd:ee:ff"))
        assertFalse(out.contains("Cafe"))
        assertFalse(out.contains("a,b)c"))
        assertFalse(out.contains("Upper"))
        assertTrue(out.contains("NetworkInfo(ssid=<redacted>, bssid=<redacted>, localIp=192.168.1.5)"))
        assertTrue(out.contains("ssid=<redacted>, ip=10.0.0.2"))
        assertTrue(out.contains("quoted ssid=<redacted> end"))
        assertTrue(out.contains("mac=11:22:33:44:55:66"))
    }
}

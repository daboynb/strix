package org.csploit.strix.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PortRangeTest {

    @Test
    fun validSpecsAreNormalized() {
        assertEquals("80,443", PortScanner.normalizePortRange("80, 443"))
        assertEquals("1-1024", PortScanner.normalizePortRange(" 1 - 1024 "))
        assertEquals("22,80-90,8000-", PortScanner.normalizePortRange("22,80-90,8000-"))
        assertEquals("-", PortScanner.normalizePortRange("-"))
        assertEquals("0-65535", PortScanner.normalizePortRange("0-65535"))
    }

    @Test
    fun invalidSpecsAreRejected() {
        listOf(
            "", " ", "80;id", "80 443x", "http", "70000", "90-80", "1-2-3", "80,,443", "443 && reboot", "\$(id)",
        ).forEach { assertNull("'$it' must be rejected", PortScanner.normalizePortRange(it)) }
    }
}

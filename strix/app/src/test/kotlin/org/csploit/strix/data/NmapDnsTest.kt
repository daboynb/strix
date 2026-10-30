package org.csploit.strix.data

import org.junit.Assert.assertEquals
import org.junit.Test

class NmapDnsTest {

    @Test
    fun configuredServerWinsOverWifi() {
        assertEquals(" --dns-servers '1.1.1.1'", NmapDns.argFor(" 1.1.1.1 ", listOf("192.168.1.1")))
    }

    @Test
    fun wifiServersAreUsedWhenNotConfigured() {
        assertEquals(" --dns-servers '192.168.1.1,8.8.8.8'", NmapDns.argFor("", listOf("192.168.1.1", "8.8.8.8")))
    }

    @Test
    fun noServersMeansNoOption() {
        assertEquals("", NmapDns.argFor("  ", emptyList()))
    }

}

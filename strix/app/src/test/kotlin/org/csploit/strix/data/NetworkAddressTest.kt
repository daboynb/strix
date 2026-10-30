package org.csploit.strix.data

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.Locale

class NetworkAddressTest {
    private val saved = Locale.getDefault()

    @After
    fun restoreLocale() = Locale.setDefault(saved)

    @Test
    fun asciiDigitsWhateverTheLocale() {
        for (tag in listOf("en-US", "ar-EG", "fa-IR")) {
            Locale.setDefault(Locale.forLanguageTag(tag))
            // 192.168.1.1 as DhcpInfo's little-endian int
            assertEquals(tag, "192.168.1.1", intToIp(0x0101A8C0))
            assertEquals(tag, "255.255.255.0", prefixToNetmask(24))
        }
    }

    @Test
    fun netmaskEdges() {
        assertEquals("0.0.0.0", prefixToNetmask(0))
        assertEquals("255.255.224.0", prefixToNetmask(19))
        assertEquals("255.255.255.255", prefixToNetmask(32))
    }
}

package org.csploit.strix.data.wifi

import org.csploit.strix.data.wifi.algorithms.EircomKeygen
import org.csploit.strix.data.wifi.algorithms.VerizonKeygen
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class KeygenFixesTest {

    @Test
    fun verizonUsesMacOctetsTwoAndThree() {
        val fallback = VerizonKeygen("1AB2C", "", 0, "WPA").getKeys()!!
        val withMac = VerizonKeygen("1AB2C", "00:1F:90:12:34:56", 0, "WPA").getKeys()!!
        assertEquals(1, withMac.size)
        assertTrue(withMac[0].startsWith("1F90"))
        // Same key as the 00:1F:90 fallback candidate.
        assertTrue(withMac[0] in fallback)
    }

    @Test
    fun eircomDerivedMacIsPaddedToThreeOctets() {
        // 00000000 octal xor 0xfcc = "fcc": shorter than 6 hex digits.
        val keygen = WirelessMatcher().getKeygen("eircom00000000", "", 0, "WPA")
        assertTrue(keygen is EircomKeygen)
        assertEquals("00:0F:CC:00:0f:cc", keygen!!.displayMac)
    }
}

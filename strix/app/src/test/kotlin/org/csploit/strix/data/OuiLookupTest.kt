package org.csploit.strix.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class OuiLookupTest {

    @Test
    fun normalizesCommonMacFormats() {
        val expected = "001A2B3C4D5E"
        assertEquals(expected, OuiLookup.normalizeMac("00:1a:2b:3c:4d:5e"))
        assertEquals(expected, OuiLookup.normalizeMac("00-1A-2B-3C-4D-5E"))
        assertEquals(expected, OuiLookup.normalizeMac("001a.2b3c.4d5e"))
        assertEquals(expected, OuiLookup.normalizeMac("001A2B3C4D5E"))
        assertEquals(expected, OuiLookup.normalizeMac("0:1a:2b:3c:4d:5e"))
    }

    @Test
    fun rejectsNonMacs() {
        assertNull(OuiLookup.normalizeMac(null))
        assertNull(OuiLookup.normalizeMac("manual"))
        assertNull(OuiLookup.normalizeMac(""))
        assertNull(OuiLookup.normalizeMac("00:1a:2b:3c:4d"))
        assertNull(OuiLookup.normalizeMac("00:1a:2b:3c:4d:5e:6f"))
    }

    @Test
    fun longestPrefixWins() {
        val db = mutableMapOf<String, String>()
        listOf(
            "# comment",
            "70B3D5 IEEE Registration Authority",
            "70B3D51 Some MA-M Vendor",
            "70B3D5123 Some MA-S Vendor",
        ).forEach { OuiLookup.parseLine(it, db) }

        assertEquals("Some MA-S Vendor", OuiLookup.lookup(db, "70B3D5123456"))
        assertEquals("Some MA-M Vendor", OuiLookup.lookup(db, "70B3D51FFFFF"))
        assertEquals("IEEE Registration Authority", OuiLookup.lookup(db, "70B3D5FFFFFF"))
        assertNull(OuiLookup.lookup(db, "AABBCCDDEEFF"))
    }
}

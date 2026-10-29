package org.csploit.strix.data

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PacketForgerTest {

    @Test
    fun normalizeMacAcceptsColonAndDash() {
        assertEquals("AA:BB:CC:DD:EE:0F", PacketForger.normalizeMac("aa:bb:cc:dd:ee:0f"))
        assertEquals("AA:BB:CC:DD:EE:0F", PacketForger.normalizeMac("AA-BB-CC-DD-EE-0F"))
    }

    @Test
    fun normalizeMacRejectsInvalid() {
        listOf(
            null, "", "manual", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff",
            "AA:BB-CC:DD:EE:FF", "AA:BB:CC:DD:EE", "AA:BB:CC:DD:EE:FG", "A:B:C:D:E:F",
        ).forEach { assertNull("$it", PacketForger.normalizeMac(it)) }
    }

    @Test
    fun buildWolPacketRejectsInvalidMacWithoutThrowing() {
        assertNull(PacketForger().buildWolPacket("manual"))
    }

    @Test
    fun buildWolPacketLayout() {
        val packet = PacketForger().buildWolPacket("01-23-45-67-89-ab")!!
        assertEquals(6 + 16 * 6, packet.size)
        assertArrayEquals(ByteArray(6) { 0xFF.toByte() }, packet.copyOfRange(0, 6))
        val mac = byteArrayOf(0x01, 0x23, 0x45, 0x67, 0x89.toByte(), 0xAB.toByte())
        for (i in 0 until 16) {
            assertArrayEquals(mac, packet.copyOfRange(6 + i * 6, 12 + i * 6))
        }
    }
}

package org.csploit.strix.data

import org.csploit.strix.domain.model.Host
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TargetRepositoryTest {

    private val mac = "D0:3C:1F:8D:6E:9A"

    @Test
    fun labellingADiscoveredHostKeepsItsMac() {
        val repo = TargetRepository()
        repo.addOrUpdate("192.168.1.32", mac, null)
        repo.addManual("192.168.1.32", "VM")
        assertEquals(listOf(Host("192.168.1.32", mac, "VM", manual = true)), repo.hosts.value)
    }

    @Test
    fun manualHostSurvivesScansAfterBeingDiscovered() {
        val repo = TargetRepository()
        repo.addManual("192.168.1.32", "VM")
        assertEquals(Host.MANUAL_MAC, repo.hosts.value.single().mac)
        repo.addOrUpdate("192.168.1.32", mac, null)
        repo.clear()
        assertEquals(listOf(Host("192.168.1.32", mac, "VM", manual = true)), repo.hosts.value)
    }

    @Test
    fun clearDropsDiscoveredHosts() {
        val repo = TargetRepository()
        repo.addOrUpdate("192.168.1.1", "7C:7D:21:B8:EF:DE", null)
        repo.clear()
        assertTrue(repo.hosts.value.isEmpty())
    }
}

package org.csploit.strix.data

import org.csploit.strix.domain.model.PortInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class NmapPortTableTest {

    private fun parseAll(vararg lines: String): List<PortInfo> {
        val table = NmapPortTable()
        return lines.mapNotNull { table.parse(it) }
    }

    @Test
    fun defaultColumns() {
        assertEquals(
            listOf(
                PortInfo(21, "tcp", "open", "ftp", "vsftpd 2.3.4"),
                PortInfo(23, "tcp", "filtered", "telnet", null),
                PortInfo(3306, "tcp", "open", "mysql", "MySQL 5.0.51a-3ubuntu5"),
            ),
            parseAll(
                "PORT     STATE    SERVICE VERSION",
                "21/tcp   open     ftp     vsftpd 2.3.4",
                "23/tcp   filtered telnet",
                "3306/tcp open     mysql   MySQL 5.0.51a-3ubuntu5",
                "MAC Address: D0:3C:1F:8D:6E:9A (Intel Corporate)",
            ),
        )
    }

    /** Real output of `nmap -sS -sV --reason` against Metasploitable2. */
    @Test
    fun reasonColumnIsNotTakenForTheVersion() {
        assertEquals(
            listOf(
                PortInfo(21, "tcp", "open", "ftp", "vsftpd 2.3.4"),
                PortInfo(22, "tcp", "open", "ssh", "OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)"),
            ),
            parseAll(
                "PORT     STATE SERVICE REASON         VERSION",
                "21/tcp   open  ftp     syn-ack ttl 64 vsftpd 2.3.4",
                "22/tcp   open  ssh     syn-ack ttl 64 OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)",
            ),
        )
    }

    @Test
    fun rowsBeforeAHeaderAreIgnored() {
        assertNull(NmapPortTable().parse("21/tcp   open  ftp     vsftpd 2.3.4"))
    }
}

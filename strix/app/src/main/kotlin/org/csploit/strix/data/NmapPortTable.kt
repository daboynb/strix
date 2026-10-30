package org.csploit.strix.data

import org.csploit.strix.domain.model.PortInfo

/**
 * nmap's port table. Columns depend on the options (custom args can add
 * REASON, e.g. `--reason`), so they are read from the header line and rows
 * are split at the header's column offsets — nmap pads every column to its
 * widest cell, header included:
 *
 *     PORT     STATE SERVICE REASON         VERSION
 *     21/tcp   open  ftp     syn-ack ttl 64 vsftpd 2.3.4
 *
 * One instance per scan: feed it every stdout line in order.
 */
internal class NmapPortTable {
    private var columns: List<Pair<String, Int>>? = null

    /** Returns the port of a table row; a header line only updates the columns. */
    fun parse(line: String): PortInfo? {
        parseHeader(line)?.let { columns = it; return null }
        val cols = columns ?: return null
        if (!ROW_REGEX.containsMatchIn(line)) return null
        val cells = cols.mapIndexed { i, (name, start) ->
            val end = cols.getOrNull(i + 1)?.second ?: line.length
            name to if (start >= line.length) "" else line.substring(start, end.coerceAtMost(line.length)).trim()
        }.toMap()
        val (number, protocol) = cells["PORT"]?.split('/')?.takeIf { it.size == 2 } ?: return null
        return PortInfo(
            number = number.toIntOrNull() ?: return null,
            protocol = protocol,
            state = cells["STATE"].orEmpty(),
            service = cells["SERVICE"]?.ifBlank { null },
            version = cells["VERSION"]?.ifBlank { null },
        )
    }

    private fun parseHeader(line: String): List<Pair<String, Int>>? {
        if (!line.startsWith("PORT ")) return null
        val cols = HEADER_WORD.findAll(line).map { it.value to it.range.first }.toList()
        return cols.takeIf { c -> c.any { it.first == "STATE" } }
    }

    private companion object {
        val ROW_REGEX = Regex("""^\d+/(tcp|udp|sctp)\s""")
        val HEADER_WORD = Regex("""[A-Z]+""")
    }
}

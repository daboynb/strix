package org.csploit.strix.data

import org.csploit.strix.domain.model.TracerouteHop

/** Parses the hop lines of `nmap --traceroute` output. */
internal object TracerouteHopParser {
    private val HOP_REGEX = Regex("""^\s*(\d+)\s+(.+)$""")
    private val RTT_ADDR_REGEX = Regex("""(\d+\.?\d*)\s+ms\s+(.+)""")
    private val HOST_IP_REGEX = Regex("""^(.+?)\s+\(([0-9.]+)\)$""")

    fun parseHop(line: String): TracerouteHop? {
        val hopMatch = HOP_REGEX.find(line) ?: return null
        val hopNumber = hopMatch.groupValues[1].toIntOrNull() ?: return null
        val rest = hopMatch.groupValues[2].trim()

        if (rest == "..." || rest.all { it == '*' || it == ' ' }) {
            return TracerouteHop(hopNumber = hopNumber, rttMs = null, address = null, hostname = null)
        }

        val rttMatch = RTT_ADDR_REGEX.find(rest) ?: return null
        val rtt = rttMatch.groupValues[1].toFloatOrNull()
        val addrPart = rttMatch.groupValues[2].trim()

        val hostIpMatch = HOST_IP_REGEX.find(addrPart)
        return if (hostIpMatch != null) {
            TracerouteHop(
                hopNumber = hopNumber,
                rttMs = rtt,
                address = hostIpMatch.groupValues[2],
                hostname = hostIpMatch.groupValues[1],
            )
        } else {
            TracerouteHop(
                hopNumber = hopNumber,
                rttMs = rtt,
                address = addrPart,
                hostname = null,
            )
        }
    }
}

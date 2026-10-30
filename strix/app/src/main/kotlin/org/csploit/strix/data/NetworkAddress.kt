package org.csploit.strix.data

// Plain string joins, not "%d".format: that uses the default locale's digits
// (Arabic/Persian give "١٩٢.١٦٨…"), which nmap and the UI can't use.

/** Dotted netmask for an IPv4 [prefixLength] (e.g. 24 → 255.255.255.0). */
internal fun prefixToNetmask(prefixLength: Int): String {
    val mask = if (prefixLength == 0) 0 else -1 shl (32 - prefixLength)
    return listOf(24, 16, 8, 0).joinToString(".") { ((mask shr it) and 0xFF).toString() }
}

/**
 * Convert little-endian int (DhcpInfo format) to IP string.
 */
internal fun intToIp(ip: Int): String =
    listOf(0, 8, 16, 24).joinToString(".") { ((ip shr it) and 0xFF).toString() }

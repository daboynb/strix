package org.csploit.strix.data

/** Dotted netmask for an IPv4 [prefixLength] (e.g. 24 → 255.255.255.0). */
internal fun prefixToNetmask(prefixLength: Int): String {
    val mask = if (prefixLength == 0) 0 else -1 shl (32 - prefixLength)
    return "%d.%d.%d.%d".format(
        (mask shr 24) and 0xFF,
        (mask shr 16) and 0xFF,
        (mask shr 8) and 0xFF,
        mask and 0xFF,
    )
}

/**
 * Convert little-endian int (DhcpInfo format) to IP string.
 */
internal fun intToIp(ip: Int): String = "%d.%d.%d.%d".format(
    ip and 0xFF,
    (ip shr 8) and 0xFF,
    (ip shr 16) and 0xFF,
    (ip shr 24) and 0xFF,
)

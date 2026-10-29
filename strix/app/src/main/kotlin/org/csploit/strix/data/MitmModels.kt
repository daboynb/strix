package org.csploit.strix.data

enum class MitmMode {
    SNIFFER,
    DNS_SPOOF,
    KILL,
}

data class DnsEntry(
    val hostname: String,
    val address: String,
)

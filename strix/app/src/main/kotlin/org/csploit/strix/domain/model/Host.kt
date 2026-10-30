package org.csploit.strix.domain.model

data class Host(
    val ip: String,
    val mac: String,
    val name: String?,
    val connected: Boolean = true,
    /** Added by the user: kept across scans (clear() drops only discovered hosts). */
    val manual: Boolean = false,
) {
    companion object {
        /** [mac] of a manual host nobody has discovered on the LAN yet. */
        const val MANUAL_MAC = "manual"
    }
}

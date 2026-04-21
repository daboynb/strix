package org.csploit.strix.domain.model

data class TracerouteHop(
    val hopNumber: Int,
    val rttMs: Float?,
    val address: String?,
    val hostname: String?,
)

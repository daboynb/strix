package org.csploit.strix.domain.model

data class Host(
    val ip: String,
    val mac: String,
    val name: String?,
    val connected: Boolean = true,
)

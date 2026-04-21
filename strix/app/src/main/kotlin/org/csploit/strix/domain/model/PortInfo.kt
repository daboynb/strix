package org.csploit.strix.domain.model

data class PortInfo(
    val number: Int,
    val protocol: String,
    val state: String,
    val service: String?,
    val version: String?,
)

package org.csploit.strix.domain.model

data class RouterInfo(
    val ip: String,
    val mac: String?,
    val manufacturer: String? = null,
    val model: String? = null,
    val firmwareVersion: String? = null,
    val httpBanner: String? = null,
    val adminPanelUrl: String? = null,
    val openPorts: List<Int> = emptyList(),
    val upnpInfo: String? = null,
    val defaultCredsFound: DefaultCreds? = null,
)

data class DefaultCreds(
    val username: String,
    val password: String,
    val service: String,
)

package org.csploit.strix.data

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.csploit.strix.domain.model.Host
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class TargetRepository @Inject constructor() {

    private val _hosts = MutableStateFlow<List<Host>>(emptyList())
    val hosts: StateFlow<List<Host>> = _hosts.asStateFlow()

    fun addOrUpdate(ip: String, mac: String, name: String?) {
        val current = _hosts.value.toMutableList()
        val index = current.indexOfFirst { it.ip == ip }
        if (index >= 0) {
            val existing = current[index]
            // Preserve existing name if new one is empty
            val resolvedName = if (!name.isNullOrBlank()) name else existing.name
            current[index] = existing.copy(
                mac = mac,
                name = resolvedName,
                connected = true,
            )
        } else {
            current.add(Host(ip = ip, mac = mac, name = name, connected = true))
        }
        _hosts.value = current
    }

    fun updateName(ip: String, name: String) {
        val current = _hosts.value.toMutableList()
        val index = current.indexOfFirst { it.ip == ip }
        if (index >= 0) {
            current[index] = current[index].copy(name = name)
            _hosts.value = current
        }
    }

    fun markDisconnected(ip: String) {
        val current = _hosts.value.toMutableList()
        val index = current.indexOfFirst { it.ip == ip }
        if (index >= 0) {
            current[index] = current[index].copy(connected = false)
            _hosts.value = current
        }
    }

    fun clear() {
        // Preserve manually added hosts across scans
        _hosts.value = _hosts.value.filter { it.mac == "manual" }
    }

    fun remove(ip: String) {
        _hosts.value = _hosts.value.filterNot { it.ip == ip }
    }
}

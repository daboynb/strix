package org.csploit.strix.data

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import org.csploit.strix.domain.model.Host
import javax.inject.Inject
import javax.inject.Singleton

/**
 * All mutations go through [MutableStateFlow.update] so concurrent writers
 * (scanner callbacks on IO threads, UI on Main) never lose each other's changes.
 */
@Singleton
class TargetRepository @Inject constructor() {

    private val _hosts = MutableStateFlow<List<Host>>(emptyList())
    val hosts: StateFlow<List<Host>> = _hosts.asStateFlow()

    /** A host found by discovery: its MAC wins, a manual host stays manual. */
    fun addOrUpdate(ip: String, mac: String, name: String?) {
        _hosts.update { hosts ->
            val current = hosts.toMutableList()
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
            current
        }
    }

    /** A host added by the user: keeps a discovered MAC, survives [clear]. */
    fun addManual(ip: String, name: String?) {
        _hosts.update { hosts ->
            val index = hosts.indexOfFirst { it.ip == ip }
            if (index >= 0) {
                val existing = hosts[index]
                hosts.toMutableList().apply {
                    this[index] = existing.copy(
                        name = if (!name.isNullOrBlank()) name else existing.name,
                        connected = true,
                        manual = true,
                    )
                }
            } else {
                hosts + Host(ip = ip, mac = Host.MANUAL_MAC, name = name, connected = true, manual = true)
            }
        }
    }

    fun updateName(ip: String, name: String) {
        _hosts.update { hosts ->
            hosts.map { if (it.ip == ip) it.copy(name = name) else it }
        }
    }

    fun markDisconnected(ip: String) {
        _hosts.update { hosts ->
            hosts.map { if (it.ip == ip) it.copy(connected = false) else it }
        }
    }

    fun clear() {
        // Preserve manually added hosts across scans
        _hosts.update { hosts -> hosts.filter { it.manual } }
    }

    fun remove(ip: String) {
        _hosts.update { hosts -> hosts.filterNot { it.ip == ip } }
    }
}

package org.csploit.strix.core

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.ContextCompat
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

data class ScanTask(val id: String, val label: String, val deepLink: Uri? = null)

/**
 * The visible side of [ScanRegistry]: the list of active tasks plus their
 * per-task notifications, and starting [ScanService] on the first task.
 */
internal class ActiveTaskList(
    private val context: Context,
    private val notifications: StrixNotifications,
) {
    private val _activeTasks = MutableStateFlow<List<ScanTask>>(emptyList())
    val activeTasks: StateFlow<List<ScanTask>> = _activeTasks.asStateFlow()

    fun register(id: String, label: String, deepLink: Uri?): ScanTask {
        val task = ScanTask(id, label, deepLink)
        val current = _activeTasks.value.toMutableList()
        current.removeAll { it.id == id }
        current.add(task)
        _activeTasks.value = current
        Logger.info("ScanRegistry: register id=$id activeTasks=${current.size}")
        notifications.notifyActiveTask(id, label, deepLink)
        if (current.size == 1) startService()
        return task
    }

    fun removeTask(id: String, predicate: (ScanTask) -> Boolean) {
        val current = _activeTasks.value.toMutableList()
        val removed = current.removeAll(predicate)
        if (removed) {
            _activeTasks.value = current
            Logger.info("ScanRegistry: unregister id=$id activeTasks=${current.size}")
            notifications.cancelActiveTask(id)
        }
    }

    private fun startService() {
        Logger.info("ScanRegistry: starting ScanService (foreground)")
        val intent = Intent(context, ScanService::class.java)
        try {
            ContextCompat.startForegroundService(context, intent)
        } catch (t: Throwable) {
            Logger.error("ScanRegistry: startForegroundService FAILED: ${t.javaClass.simpleName}: ${t.message}")
        }
    }
}

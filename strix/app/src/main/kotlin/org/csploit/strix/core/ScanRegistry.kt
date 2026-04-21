package org.csploit.strix.core

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.ContextCompat
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.isActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.coroutines.cancellation.CancellationException as KCancellationException

data class ScanTask(val id: String, val label: String, val deepLink: Uri? = null)

/**
 * Hosts long-running scan coroutines in an application-scoped CoroutineScope
 * so they survive ViewModel destruction (navigation, config changes).
 *
 * Drives [ScanService] lifecycle: starts the foreground service on first
 * active task, the service stops itself when the last one unregisters.
 */
@Singleton
class ScanRegistry @Inject constructor(
    @ApplicationContext private val context: Context,
    val notifications: StrixNotifications,
) {
    val appScope: CoroutineScope =
        CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    private val jobs = ConcurrentHashMap<String, Job>()
    private val _activeTasks = MutableStateFlow<List<ScanTask>>(emptyList())
    val activeTasks: StateFlow<List<ScanTask>> = _activeTasks.asStateFlow()

    /**
     * Launch [block] in the application scope, registered under [id].
     * If an active task with the same id exists, it is cancelled first.
     * The task auto-unregisters when [block] finishes (normally or via cancel).
     */
    fun launch(
        id: String,
        label: String,
        deepLink: Uri? = null,
        block: suspend CoroutineScope.() -> Unit,
    ): Job {
        jobs.remove(id)?.let {
            Logger.info("ScanRegistry: cancelling previous task id=$id (replaced)")
            it.cancel(CancellationException("replaced by new task with same id"))
        }

        register(id, label, deepLink)
        Logger.info("ScanRegistry: launch id=$id label='$label' appScope.isActive=${appScope.isActive}")
        val job = appScope.launch {
            try {
                block()
                Logger.info("ScanRegistry: block finished NORMALLY id=$id")
            } catch (ce: KCancellationException) {
                Logger.info("ScanRegistry: block CANCELLED id=$id reason='${ce.message}'")
                throw ce
            } catch (t: Throwable) {
                Logger.error("ScanRegistry: block THREW id=$id: ${t.javaClass.simpleName}: ${t.message}")
                throw t
            } finally {
                unregister(id)
            }
        }
        jobs[id] = job
        return job
    }

    fun cancel(id: String) {
        Logger.info("ScanRegistry: cancel(id=$id) called")
        jobs.remove(id)?.cancel()
        unregister(id)
    }

    fun isActive(id: String): Boolean = jobs[id]?.isActive == true

    private fun register(id: String, label: String, deepLink: Uri?) {
        val current = _activeTasks.value.toMutableList()
        current.removeAll { it.id == id }
        current.add(ScanTask(id, label, deepLink))
        _activeTasks.value = current
        Logger.info("ScanRegistry: register id=$id activeTasks=${current.size}")
        notifications.notifyActiveTask(id, label, deepLink)
        if (current.size == 1) startService()
    }

    private fun unregister(id: String) {
        jobs.remove(id)
        val current = _activeTasks.value.toMutableList()
        val removed = current.removeAll { it.id == id }
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

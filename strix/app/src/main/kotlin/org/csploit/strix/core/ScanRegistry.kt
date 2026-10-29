package org.csploit.strix.core

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.ContextCompat
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.isActive
import kotlinx.coroutines.job
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
    // Last-resort handler: a failing task must never crash the app. Callers
    // get the failure through launch(onError = ...).
    private val exceptionHandler = CoroutineExceptionHandler { _, t ->
        Logger.error("ScanRegistry: unhandled ${t.javaClass.simpleName}: ${t.message}")
    }

    val appScope: CoroutineScope =
        CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate + exceptionHandler)

    private val jobs = ConcurrentHashMap<String, Job>()
    private val _activeTasks = MutableStateFlow<List<ScanTask>>(emptyList())
    val activeTasks: StateFlow<List<ScanTask>> = _activeTasks.asStateFlow()

    /**
     * Launch [block] in the application scope, registered under [id].
     * If an active task with the same id exists, it is cancelled first.
     * The task auto-unregisters when [block] finishes (normally or via cancel);
     * a replaced task's cleanup never touches its successor's registration.
     * [onError] is called on the main thread if the task fails with a
     * non-cancellation exception (including failures of its child coroutines).
     */
    fun launch(
        id: String,
        label: String,
        deepLink: Uri? = null,
        onError: ((Throwable) -> Unit)? = null,
        block: suspend CoroutineScope.() -> Unit,
    ): Job {
        jobs.remove(id)?.let {
            Logger.info("ScanRegistry: cancelling previous task id=$id (replaced)")
            it.cancel(CancellationException("replaced by new task with same id"))
        }

        val task = register(id, label, deepLink)
        Logger.info("ScanRegistry: launch id=$id label='$label' appScope.isActive=${appScope.isActive}")
        // LAZY so the job is in [jobs] before the block can run (and finish) on Main.immediate.
        val job = appScope.launch(start = CoroutineStart.LAZY) {
            val self = coroutineContext.job
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
                unregister(id, self, task)
            }
        }
        jobs[id] = job
        job.invokeOnCompletion { cause ->
            if (cause != null && cause !is KCancellationException && onError != null) {
                appScope.launch { onError(cause) }
            }
        }
        job.start()
        return job
    }

    fun cancel(id: String) {
        Logger.info("ScanRegistry: cancel(id=$id) called")
        jobs.remove(id)?.cancel()
        removeTask(id) { it.id == id }
    }

    fun isActive(id: String): Boolean = jobs[id]?.isActive == true

    /** True if [job] was registered under [id] and has since been replaced by a newer launch. */
    fun isReplaced(id: String, job: Job): Boolean = jobs[id].let { it != null && it !== job }

    private fun register(id: String, label: String, deepLink: Uri?): ScanTask {
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

    /** Remove only this launch's job and task entry; a newer task with the same id is left alone. */
    private fun unregister(id: String, job: Job, task: ScanTask) {
        jobs.remove(id, job)
        removeTask(id) { it === task }
    }

    private fun removeTask(id: String, predicate: (ScanTask) -> Boolean) {
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

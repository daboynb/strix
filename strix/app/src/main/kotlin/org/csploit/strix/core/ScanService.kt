package org.csploit.strix.core

import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationManagerCompat
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Foreground service that keeps the app process alive while any scan is active.
 * Observes [ScanRegistry.activeTasks] — updates the persistent notification on
 * changes and stops itself when the list goes empty.
 */
@AndroidEntryPoint
class ScanService : Service() {

    @Inject lateinit var registry: ScanRegistry
    @Inject lateinit var notifications: StrixNotifications

    private val scope = CoroutineScope(SupervisorJob() + kotlinx.coroutines.Dispatchers.Main.immediate)
    private var observerJob: Job? = null
    private var started = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Logger.info("ScanService: onStartCommand started=$started activeTasks=${registry.activeTasks.value.size}")
        if (!started) {
            started = true
            val initial = notifications.buildForegroundNotification(
                registry.activeTasks.value.map { it.label },
            )
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    startForeground(
                        StrixNotifications.FOREGROUND_NOTIF_ID,
                        initial,
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
                    )
                } else {
                    startForeground(StrixNotifications.FOREGROUND_NOTIF_ID, initial)
                }
                Logger.info("ScanService: startForeground OK")
            } catch (t: Throwable) {
                Logger.error("ScanService: startForeground FAILED: ${t.javaClass.simpleName}: ${t.message}")
            }

            observerJob = scope.launch {
                registry.activeTasks.collectLatest { tasks ->
                    Logger.debug("ScanService: activeTasks update size=${tasks.size}")
                    if (tasks.isEmpty()) {
                        Logger.info("ScanService: no active tasks, stopping self")
                        stopSelfSafely()
                    } else {
                        try {
                            NotificationManagerCompat.from(this@ScanService).notify(
                                StrixNotifications.FOREGROUND_NOTIF_ID,
                                notifications.buildForegroundNotification(tasks.map { it.label }),
                            )
                        } catch (t: Throwable) {
                            Logger.error("ScanService: notification update failed: ${t.message}")
                        }
                    }
                }
            }
        }
        return START_STICKY
    }

    private fun stopSelfSafely() {
        observerJob?.cancel()
        observerJob = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        started = false
    }

    override fun onDestroy() {
        Logger.info("ScanService: onDestroy")
        scope.cancel()
        super.onDestroy()
    }
}

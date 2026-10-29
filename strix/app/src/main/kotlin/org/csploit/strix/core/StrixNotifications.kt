package org.csploit.strix.core

import android.app.Notification
import android.content.Context
import android.net.Uri
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import dagger.hilt.android.qualifiers.ApplicationContext
import org.csploit.strix.R
import java.util.concurrent.atomic.AtomicInteger
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class StrixNotifications @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    private val nextId = AtomicInteger(10_000)

    fun createChannels() = createStrixChannels(context)

    fun buildForegroundNotification(activeLabels: List<String>): Notification {
        val count = activeLabels.size
        val title = when (count) {
            0 -> "Strix"
            1 -> "1 task running"
            else -> "$count tasks running"
        }
        return NotificationCompat.Builder(context, CHANNEL_SCANS)
            .setSmallIcon(R.drawable.ic_strix_notification)
            .setContentTitle(title)
            .setContentText("Tap a task notification to open it")
            .setContentIntent(launchIntent(context, null))
            .setOngoing(true)
            .setSilent(true)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setGroup(GROUP_ACTIVE_TASKS)
            .setGroupSummary(true)
            .build()
    }

    /**
     * Per-task ongoing notification — one per concurrently running scan so the
     * user can tap the specific task to open its screen. Posts under an id
     * derived from [tag] so re-registering the same tag updates rather than
     * duplicates the notification. Swipe-away is disabled via ongoing.
     */
    fun notifyActiveTask(tag: String, label: String, deepLink: Uri?) {
        val manager = NotificationManagerCompat.from(context)
        if (!manager.areNotificationsEnabled()) return
        val notif = NotificationCompat.Builder(context, CHANNEL_SCANS)
            .setSmallIcon(R.drawable.ic_strix_notification)
            .setContentTitle(label)
            .setContentText("Running — tap to open")
            .setContentIntent(launchIntent(context, deepLink))
            .setOngoing(true)
            .setSilent(true)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setGroup(GROUP_ACTIVE_TASKS)
            .build()
        try {
            manager.notify(taskNotifId(tag), notif)
        } catch (e: SecurityException) {
            Logger.warning("StrixNotifications: notifyActiveTask SecurityException: ${e.message}")
        }
    }

    fun cancelActiveTask(tag: String) {
        NotificationManagerCompat.from(context).cancel(taskNotifId(tag))
    }

    fun notifyScanComplete(title: String, message: String, deepLink: Uri? = null) {
        post(scanCompleteNotification(context, title, message, deepLink))
    }

    fun notifyCredentialCaptured(host: String, credential: String, deepLink: Uri? = null) {
        post(credentialCapturedNotification(context, host, credential, deepLink))
    }

    fun notifySessionOpened(sessionId: Int, info: String) {
        post(sessionOpenedNotification(context, sessionId, info))
    }

    private fun post(notification: Notification) {
        val manager = NotificationManagerCompat.from(context)
        if (!manager.areNotificationsEnabled()) {
            Logger.warning("StrixNotifications: DROP — notifications disabled for app (POST_NOTIFICATIONS denied?)")
            return
        }
        val id = nextId.incrementAndGet()
        try {
            manager.notify(id, notification)
            Logger.info("StrixNotifications: posted id=$id")
        } catch (e: SecurityException) {
            Logger.warning("StrixNotifications: SecurityException posting id=$id: ${e.message}")
        }
    }

    companion object {
        const val CHANNEL_SCANS = "strix_scans"
        const val CHANNEL_EVENTS = "strix_events"
        const val FOREGROUND_NOTIF_ID = 1
        const val GROUP_ACTIVE_TASKS = "strix_active_tasks"
    }
}

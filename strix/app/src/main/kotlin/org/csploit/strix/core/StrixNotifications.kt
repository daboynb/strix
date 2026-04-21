package org.csploit.strix.core

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import dagger.hilt.android.qualifiers.ApplicationContext
import org.csploit.strix.MainActivity
import org.csploit.strix.R
import java.util.concurrent.atomic.AtomicInteger
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class StrixNotifications @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    private val nextId = AtomicInteger(10_000)

    fun createChannels() {
        val enabled = NotificationManagerCompat.from(context).areNotificationsEnabled()
        Logger.info("StrixNotifications: createChannels (areNotificationsEnabled=$enabled)")
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_SCANS,
                "Active scans",
                NotificationManager.IMPORTANCE_DEFAULT,
            ).apply {
                description = "Persistent foreground notification while scans run."
                setShowBadge(false)
                enableVibration(false)
                setSound(null, null)
            },
        )
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_EVENTS,
                "Scan events",
                NotificationManager.IMPORTANCE_DEFAULT,
            ).apply {
                description = "Scan complete, session opened, credential captured."
            },
        )
    }

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
            .setContentIntent(launchIntent(null))
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
            .setContentIntent(launchIntent(deepLink))
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

    /** Stable, positive int id from [tag] — avoids colliding with [FOREGROUND_NOTIF_ID] (1) or the event counter (>=10_001). */
    private fun taskNotifId(tag: String): Int {
        val h = tag.hashCode()
        val positive = if (h == Int.MIN_VALUE) 0 else (h and 0x7FFFFFFF)
        return 100 + (positive % 9_000) // [100, 9099]
    }

    fun notifyScanComplete(title: String, message: String, deepLink: Uri? = null) {
        post(
            NotificationCompat.Builder(context, CHANNEL_EVENTS)
                .setSmallIcon(R.drawable.ic_strix_notification)
                .setContentTitle(title)
                .setContentText(message)
                .setStyle(NotificationCompat.BigTextStyle().bigText(message))
                .setContentIntent(launchIntent(deepLink))
                .setAutoCancel(true)
                .build(),
        )
    }

    fun notifyCredentialCaptured(host: String, credential: String, deepLink: Uri? = null) {
        post(
            NotificationCompat.Builder(context, CHANNEL_EVENTS)
                .setSmallIcon(R.drawable.ic_strix_notification)
                .setContentTitle("Credential captured — $host")
                .setContentText(credential)
                .setStyle(NotificationCompat.BigTextStyle().bigText(credential))
                .setContentIntent(launchIntent(deepLink))
                .setAutoCancel(true)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .build(),
        )
    }

    fun notifySessionOpened(sessionId: Int, info: String) {
        val deepLink = Uri.parse("strix://msf_shell/$sessionId")
        post(
            NotificationCompat.Builder(context, CHANNEL_EVENTS)
                .setSmallIcon(R.drawable.ic_strix_notification)
                .setContentTitle("MSF session #$sessionId opened")
                .setContentText(info)
                .setStyle(NotificationCompat.BigTextStyle().bigText(info))
                .setContentIntent(launchIntent(deepLink))
                .setAutoCancel(true)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .build(),
        )
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

    /**
     * PendingIntent that reopens MainActivity. If [deepLink] is provided, it is
     * set as Intent.data so Compose Navigation's deep-link handling can route to
     * the specific destination (requires matching navDeepLink on the composable).
     */
    private fun launchIntent(deepLink: Uri?): PendingIntent {
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            if (deepLink != null) {
                action = Intent.ACTION_VIEW
                data = deepLink
            }
        }
        // Use deepLink's hashCode as request code so distinct deep links get
        // distinct PendingIntents (otherwise FLAG_UPDATE_CURRENT would collapse
        // them and every notification would open the same screen).
        val requestCode = deepLink?.toString()?.hashCode() ?: 0
        return PendingIntent.getActivity(
            context,
            requestCode,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    companion object {
        const val CHANNEL_SCANS = "strix_scans"
        const val CHANNEL_EVENTS = "strix_events"
        const val FOREGROUND_NOTIF_ID = 1
        const val GROUP_ACTIVE_TASKS = "strix_active_tasks"
    }
}

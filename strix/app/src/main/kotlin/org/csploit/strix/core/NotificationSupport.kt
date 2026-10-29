package org.csploit.strix.core

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.app.NotificationManagerCompat
import org.csploit.strix.MainActivity
import org.csploit.strix.core.StrixNotifications.Companion.CHANNEL_EVENTS
import org.csploit.strix.core.StrixNotifications.Companion.CHANNEL_SCANS

internal fun createStrixChannels(context: Context) {
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

/** Stable, positive int id from [tag] — avoids colliding with [StrixNotifications.FOREGROUND_NOTIF_ID] (1) or the event counter (>=10_001). */
internal fun taskNotifId(tag: String): Int {
    val h = tag.hashCode()
    val positive = if (h == Int.MIN_VALUE) 0 else (h and 0x7FFFFFFF)
    return 100 + (positive % 9_000) // [100, 9099]
}

/**
 * PendingIntent that reopens MainActivity. If [deepLink] is provided, it is
 * set as Intent.data so Compose Navigation's deep-link handling can route to
 * the specific destination (requires matching navDeepLink on the composable).
 */
internal fun launchIntent(context: Context, deepLink: Uri?): PendingIntent {
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

package org.csploit.strix.core

import android.app.Notification
import android.content.Context
import android.net.Uri
import androidx.core.app.NotificationCompat
import org.csploit.strix.R
import org.csploit.strix.core.StrixNotifications.Companion.CHANNEL_EVENTS

// Content of the one-shot event notifications posted by [StrixNotifications].

internal fun scanCompleteNotification(context: Context, title: String, message: String, deepLink: Uri?): Notification =
    NotificationCompat.Builder(context, CHANNEL_EVENTS)
        .setSmallIcon(R.drawable.ic_strix_notification)
        .setContentTitle(title)
        .setContentText(message)
        .setStyle(NotificationCompat.BigTextStyle().bigText(message))
        .setContentIntent(launchIntent(context, deepLink))
        .setAutoCancel(true)
        .build()

internal fun credentialCapturedNotification(context: Context, host: String, credential: String, deepLink: Uri?): Notification =
    NotificationCompat.Builder(context, CHANNEL_EVENTS)
        .setSmallIcon(R.drawable.ic_strix_notification)
        .setContentTitle("Credential captured — $host")
        .setContentText(credential)
        .setStyle(NotificationCompat.BigTextStyle().bigText(credential))
        .setContentIntent(launchIntent(context, deepLink))
        .setAutoCancel(true)
        .setPriority(NotificationCompat.PRIORITY_HIGH)
        .build()

internal fun sessionOpenedNotification(context: Context, sessionId: Int, info: String): Notification {
    val deepLink = Uri.parse("strix://msf_shell/$sessionId")
    return NotificationCompat.Builder(context, CHANNEL_EVENTS)
        .setSmallIcon(R.drawable.ic_strix_notification)
        .setContentTitle("MSF session #$sessionId opened")
        .setContentText(info)
        .setStyle(NotificationCompat.BigTextStyle().bigText(info))
        .setContentIntent(launchIntent(context, deepLink))
        .setAutoCancel(true)
        .setPriority(NotificationCompat.PRIORITY_HIGH)
        .build()
}

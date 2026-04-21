package org.csploit.strix

import android.app.Application
import android.os.Handler
import android.os.Looper
import android.webkit.WebView
import dagger.hilt.android.HiltAndroidApp
import org.csploit.strix.core.StrixNotifications
import javax.inject.Inject

@HiltAndroidApp
class StrixApplication : Application() {

    @Inject lateinit var notifications: StrixNotifications

    override fun onCreate() {
        super.onCreate()

        notifications.createChannels()

        // Pre-warm the WebView/Chromium runtime on a background tick so the
        // first WebView used by BruteForceScreen does not lazy-init Chromium
        // during Compose measurement (which sizes the AndroidView with the
        // wrong constraints, eating the entire screen).
        Handler(Looper.getMainLooper()).post {
            try {
                WebView(this).destroy()
            } catch (_: Throwable) {
            }
        }
    }
}

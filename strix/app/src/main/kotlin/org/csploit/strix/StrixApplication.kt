package org.csploit.strix

import android.app.Application
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.webkit.WebView
import dagger.hilt.android.HiltAndroidApp
import org.csploit.strix.core.Logger
import org.csploit.strix.core.StrixNotifications
import java.io.File
import javax.inject.Inject
import kotlin.system.exitProcess

@HiltAndroidApp
class StrixApplication : Application() {

    @Inject lateinit var notifications: StrixNotifications

    override fun onCreate() {
        // Before super.onCreate(): Hilt builds singletons there and their logs belong in the file too.
        Logger.init(File(filesDir, "logs"))
        installCrashHandler()
        super.onCreate()
        Logger.info("Process start pid=${Process.myPid()}")

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

    /** Writes the crash to the log file synchronously, then lets the previous handler kill the app. */
    private fun installCrashHandler() {
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            try {
                Logger.crash(thread, throwable)
            } catch (_: Throwable) {
            }
            if (previous != null) {
                previous.uncaughtException(thread, throwable)
            } else {
                Process.killProcess(Process.myPid())
                exitProcess(10)
            }
        }
    }
}

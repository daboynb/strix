package org.csploit.strix.core

import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File

/**
 * App-wide logging: logcat always; after [init] (StrixApplication.onCreate)
 * also filesDir/logs/strix.log through [LogFileSink] (background writer, no
 * disk IO on the calling thread). Before [init] (e.g. JVM unit tests) only logcat.
 */
object Logger {
    private const val TAG = "STRIX"

    @Volatile private var sink: LogFileSink? = null
    private val _changes = MutableStateFlow(0L)

    /** Bumped after every batch written to (or clear of) the log file. */
    val changes: StateFlow<Long> = _changes.asStateFlow()

    fun init(dir: File) {
        if (sink != null) return
        synchronized(this) {
            if (sink == null) sink = LogFileSink(dir, onWritten = { _changes.value++ })
        }
    }

    fun debug(message: String) = log(LogLevel.DEBUG, message, null)

    fun info(message: String) = log(LogLevel.INFO, message, null)

    fun warning(message: String) = log(LogLevel.WARN, message, null)

    fun error(message: String) = log(LogLevel.ERROR, message, null)

    fun error(message: String, throwable: Throwable) = log(LogLevel.ERROR, message, throwable)

    /** Synchronously records an uncaught exception (the process is about to die). */
    fun crash(thread: Thread, throwable: Throwable) {
        val tag = "$TAG[crash]"
        val message = "Uncaught exception in thread \"${thread.name}\""
        Log.e(tag, message, throwable)
        sink?.writeSync(LogFormat.format(System.currentTimeMillis(), LogLevel.ERROR, tag, message, throwable))
    }

    /** Rotated + current log file content, oldest first; empty before [init]. Does file IO. */
    fun readLog(): String = sink?.readAll() ?: ""

    /** Deletes the log files. Does file IO. */
    fun clearLog() {
        sink?.clear()
    }

    /** Waits until every queued line is on disk. Does file IO. */
    fun flush() {
        sink?.flush()
    }

    /** Test hook: stop the file sink and go back to logcat-only. */
    internal fun detach() {
        synchronized(this) {
            sink?.close()
            sink = null
        }
    }

    private fun log(level: LogLevel, message: String, throwable: Throwable?) {
        val tag = "$TAG[${callerInfo()}]"
        when (level) {
            LogLevel.DEBUG -> Log.d(tag, message)
            LogLevel.INFO -> Log.i(tag, message)
            LogLevel.WARN -> Log.w(tag, message)
            LogLevel.ERROR -> if (throwable != null) Log.e(tag, message, throwable) else Log.e(tag, message)
        }
        sink?.append(LogFormat.format(System.currentTimeMillis(), level, tag, message, throwable))
    }

    private fun callerInfo(): String {
        val stack = Thread.currentThread().stackTrace
        for (element in stack) {
            val cls = element.className
            if (cls.startsWith("org.csploit.strix.") && cls != Logger::class.java.name) {
                val shortClass = cls.removePrefix("org.csploit.strix.")
                return "$shortClass.${element.methodName}"
            }
        }
        return "unknown"
    }
}

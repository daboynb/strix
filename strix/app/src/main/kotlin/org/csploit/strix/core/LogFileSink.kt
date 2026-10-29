package org.csploit.strix.core

import android.util.Log
import java.io.File
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Semaphore
import java.util.concurrent.atomic.AtomicInteger

/**
 * Appends preformatted log text to [dir]/strix.log on one background thread.
 * [append] never touches the disk (bounded queue, lines are dropped and counted
 * when it is full). Size-rotated: when strix.log would exceed [maxBytes] it
 * becomes strix.log.1 (the previous .1 is deleted).
 *
 * Queued items are only removed while holding [lock], so the writer thread and
 * synchronous callers ([writeSync], [readAll]) keep the original order.
 * Never calls [Logger] (recursion): problems go to logcat only.
 */
class LogFileSink(
    val dir: File,
    private val maxBytes: Long = DEFAULT_MAX_BYTES,
    queueCapacity: Int = 10_000,
    private val onWritten: () -> Unit = {},
) {
    val current = File(dir, FILE_NAME)
    val rotated = File(dir, "$FILE_NAME.1")

    internal val lock = Any()
    private val queue = ArrayBlockingQueue<String>(queueCapacity)
    private val signal = Semaphore(0)
    private val dropped = AtomicInteger()
    private val file = RotatingLogFile(dir, current, rotated, maxBytes)
    @Volatile private var stopped = false

    private val thread = Thread(::run, "strix-log-writer").apply {
        isDaemon = true
        start()
    }

    fun append(text: String) {
        if (queue.offer(text)) signal.release() else dropped.incrementAndGet()
    }

    /** Writes [text] (after everything queued) and flushes before returning. Crash path. */
    fun writeSync(text: String) {
        synchronized(lock) {
            drainLocked()
            writeLocked(text)
            flushLocked()
        }
        onWritten()
    }

    /** Rotated file followed by the current one: oldest first. */
    fun readAll(): String = synchronized(lock) {
        drainLocked()
        flushLocked()
        buildString {
            if (rotated.exists()) append(rotated.readText())
            if (current.exists()) append(current.readText())
        }
    }

    fun clear() {
        synchronized(lock) {
            queue.clear()
            dropped.set(0)
            closeLocked()
            rotated.delete()
            current.delete()
        }
        onWritten()
    }

    /** Waits until everything queued so far is on disk. */
    fun flush() {
        synchronized(lock) {
            drainLocked()
            flushLocked()
        }
    }

    fun close() {
        stopped = true
        thread.interrupt()
        synchronized(lock) {
            drainLocked()
            closeLocked()
        }
    }

    private fun run() {
        while (!stopped) {
            try {
                signal.acquire()
                signal.drainPermits()
                synchronized(lock) {
                    drainLocked()
                    flushLocked()
                }
                onWritten()
            } catch (_: InterruptedException) {
                return
            } catch (t: Throwable) {
                Log.w(TAG, "log writer error", t)
            }
        }
    }

    private fun drainLocked() {
        while (true) {
            val next = queue.poll() ?: break
            writeLocked(next)
        }
        val lost = dropped.getAndSet(0)
        if (lost > 0) {
            writeLocked(LogFormat.format(System.currentTimeMillis(), LogLevel.WARN, "STRIX[log]", "$lost log lines dropped (queue full)"))
        }
    }

    private fun writeLocked(text: String) = file.write(text)

    private fun flushLocked() = file.flush()

    private fun closeLocked() = file.close()

    companion object {
        const val FILE_NAME = "strix.log"
        const val DEFAULT_MAX_BYTES = 1L * 1024 * 1024
        private const val TAG = "STRIX[log]"
    }
}

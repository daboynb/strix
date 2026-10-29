package org.csploit.strix.core

import android.util.Log
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.OutputStream

/**
 * Size-rotated append target for [LogFileSink]: when [current] would exceed
 * [maxBytes] it becomes [rotated] (the previous one is deleted). Not
 * thread-safe: every call happens under [LogFileSink.lock].
 * Never calls [Logger] (recursion): problems go to logcat only.
 */
internal class RotatingLogFile(
    private val dir: File,
    private val current: File,
    private val rotated: File,
    private val maxBytes: Long,
) {
    private var out: OutputStream? = null
    private var size = 0L

    fun write(text: String) {
        val bytes = text.toByteArray(Charsets.UTF_8)
        try {
            if (out == null) open()
            if (size > 0 && size + bytes.size > maxBytes) rotate()
            out!!.write(bytes)
            size += bytes.size
        } catch (e: IOException) {
            Log.w(TAG, "log write failed: ${e.message}")
            close()
        }
    }

    fun flush() {
        try {
            out?.flush()
        } catch (e: IOException) {
            Log.w(TAG, "log flush failed: ${e.message}")
            close()
        }
    }

    fun close() {
        try {
            out?.close()
        } catch (_: IOException) {
        }
        out = null
        size = 0
    }

    private fun open() {
        dir.mkdirs()
        size = current.length()
        out = BufferedOutputStream(FileOutputStream(current, true))
    }

    private fun rotate() {
        close()
        rotated.delete()
        if (!current.renameTo(rotated)) current.delete()
        open()
    }

    private companion object {
        const val TAG = "STRIX[log]"
    }
}

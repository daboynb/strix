package org.csploit.strix.core

import java.io.PrintWriter
import java.io.StringWriter
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter

enum class LogLevel(val letter: Char) {
    DEBUG('D'), INFO('I'), WARN('W'), ERROR('E');

    companion object {
        fun fromLetter(c: Char): LogLevel? = entries.firstOrNull { it.letter == c }
    }
}

/** One log record; [message] includes continuation lines (multi-line messages, stack traces). */
data class LogEntry(
    val timestamp: String,
    val level: LogLevel,
    val tag: String,
    val message: String,
) {
    fun toText(): String =
        if (timestamp.isEmpty()) message else "$timestamp ${level.letter} $tag: $message"
}

/**
 * Line format of filesDir/logs/strix.log:
 * `2026-10-29T14:03:12.345 I STRIX[data.NetworkManager.detect]: message`
 * followed by continuation lines (no header) for multi-line messages and stack traces.
 */
object LogFormat {
    private val TIMESTAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS")
    private val HEADER = Regex("""^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}) ([DIWE]) (\S+): (.*)$""")
    // ssid=... / bssid=... up to the next comma, paren or line end; a quoted value up to its closing quote.
    private val WIFI_ID = Regex("""(?i)\b(b?ssid)=("[^"\n]*"|[^,)\n]*)""")

    fun timestamp(millis: Long): String =
        LocalDateTime.ofInstant(Instant.ofEpochMilli(millis), ZoneId.systemDefault()).format(TIMESTAMP)

    /** One complete entry, newline-terminated. */
    fun format(millis: Long, level: LogLevel, tag: String, message: String, throwable: Throwable? = null): String {
        val sb = StringBuilder()
        sb.append(timestamp(millis)).append(' ').append(level.letter).append(' ')
            .append(tag).append(": ").append(message.trimEnd('\n'))
        if (throwable != null) sb.append('\n').append(stackTrace(throwable).trimEnd())
        return sb.append('\n').toString()
    }

    fun stackTrace(throwable: Throwable): String {
        val sw = StringWriter()
        PrintWriter(sw).use { throwable.printStackTrace(it) }
        return sw.toString()
    }

    fun parse(text: String): List<LogEntry> {
        val out = ArrayList<LogEntry>()
        var current: LogEntry? = null
        val continuation = StringBuilder()
        fun close() {
            current?.let {
                out += if (continuation.isEmpty()) it else it.copy(message = it.message + continuation)
            }
            continuation.setLength(0)
        }
        for (line in text.lineSequence()) {
            val match = HEADER.matchEntire(line)
            if (match != null) {
                close()
                val (ts, letter, tag, message) = match.destructured
                current = LogEntry(ts, LogLevel.fromLetter(letter[0]) ?: LogLevel.INFO, tag, message)
            } else if (current != null) {
                continuation.append('\n').append(line)
            } else if (line.isNotEmpty()) {
                out += LogEntry("", LogLevel.INFO, "", line)
            }
        }
        close()
        // The file ends with '\n': drop the empty trailing continuation it produces.
        return out.map { if (it.message.endsWith('\n')) it.copy(message = it.message.trimEnd('\n')) else it }
    }

    fun filter(entries: List<LogEntry>, minLevel: LogLevel, query: String): List<LogEntry> {
        val q = query.trim()
        return entries.filter {
            it.level >= minLevel &&
                (q.isEmpty() || it.message.contains(q, ignoreCase = true) || it.tag.contains(q, ignoreCase = true))
        }
    }

    /** Hides Wi-Fi SSID/BSSID values; MAC addresses of hosts are kept on purpose. */
    fun redact(text: String): String = WIFI_ID.replace(text) { "${it.groupValues[1]}=<redacted>" }
}

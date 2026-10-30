package org.csploit.strix.ui.settings

/**
 * "just now", "5 minutes ago", "1 hour ago", "3 days ago": English like the
 * rest of the UI (DateUtils.getRelativeTimeSpanString follows the device
 * locale and gives "0 minuti fa" next to English text).
 */
internal fun relativeTime(thenMs: Long, nowMs: Long): String {
    val seconds = (nowMs - thenMs).coerceAtLeast(0) / 1000
    fun ago(n: Long, unit: String) = "$n $unit${if (n == 1L) "" else "s"} ago"
    return when {
        seconds < 60 -> "just now"
        seconds < 3600 -> ago(seconds / 60, "minute")
        seconds < 86_400 -> ago(seconds / 3600, "hour")
        else -> ago(seconds / 86_400, "day")
    }
}

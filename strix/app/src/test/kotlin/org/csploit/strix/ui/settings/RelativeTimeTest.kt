package org.csploit.strix.ui.settings

import org.junit.Assert.assertEquals
import org.junit.Test

class RelativeTimeTest {
    private val now = 10_000_000_000L
    private fun ago(seconds: Long) = relativeTime(now - seconds * 1000, now)

    @Test
    fun englishUnitsWithPlurals() {
        assertEquals("just now", ago(0))
        assertEquals("just now", ago(59))
        assertEquals("1 minute ago", ago(60))
        assertEquals("59 minutes ago", ago(3599))
        assertEquals("1 hour ago", ago(3600))
        assertEquals("21 hours ago", ago(21 * 3600 + 5))
        assertEquals("1 day ago", ago(86_400))
        assertEquals("3 days ago", ago(3 * 86_400))
    }

    @Test
    fun futureTimestampsClampToNow() {
        assertEquals("just now", relativeTime(now + 60_000, now))
    }
}

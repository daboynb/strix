package org.csploit.strix.data.bundle

import org.junit.Assert.assertEquals
import org.junit.Test

class BundleLabelsTest {
    private fun m(version: String, built: Long?) =
        BundleManifest(1, "msf", version, "f.bin", "a".repeat(64), 1, 1, 3, built)

    @Test
    fun rebuildOfTheSameVersionShowsBuildTimes() {
        // Real manifests: CI build installed by hand vs the first published release
        assertEquals(
            "msf 6.4.125 (built 2026-10-30 13:28 UTC)" to "msf 6.4.125 (built 2026-10-30 20:25 UTC)",
            versionLabels("msf 6.4.125", m("msf 6.4.125", 1793366922), m("msf 6.4.125", 1793391924)),
        )
    }

    @Test
    fun differentVersionsStayPlain() {
        assertEquals(
            "msf 6.4.125" to "msf 6.4.126",
            versionLabels("msf 6.4.125", m("msf 6.4.125", 1), m("msf 6.4.126", 2)),
        )
    }

    @Test
    fun nothingOfferedOrNoManifest() {
        assertEquals("msf 6.4.125" to null, versionLabels("msf 6.4.125", m("msf 6.4.125", 1), null))
        assertEquals(BundleVersions.LEGACY to "msf 6.4.125", versionLabels(BundleVersions.LEGACY, null, m("msf 6.4.125", 1)))
    }

    @Test
    fun missingBuiltFallsBackToTheVersion() {
        assertEquals(
            "msf 6.4.125" to "msf 6.4.125 (built 2026-10-30 20:25 UTC)",
            versionLabels("msf 6.4.125", m("msf 6.4.125", null), m("msf 6.4.125", 1793391924)),
        )
    }
}

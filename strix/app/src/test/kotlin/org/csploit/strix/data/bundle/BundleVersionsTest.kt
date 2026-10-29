package org.csploit.strix.data.bundle

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BundleVersionsTest {
    private fun m(version: String, built: Long?, sha: Char = 'a', id: String = "tools") =
        BundleManifest(1, id, version, "f.bin", sha.toString().repeat(64), 1, 1, 1, built)

    private fun lt(a: String, b: String) {
        assertTrue("$a < $b", BundleVersions.compareVersions(a, b) < 0)
        assertTrue("$b > $a", BundleVersions.compareVersions(b, a) > 0)
    }

    @Test fun versionStringOrdering() {
        lt("6.4.125-r1", "6.4.125-r2")
        lt("6.4.125-r2", "6.4.126-r1")
        lt("6.4.9", "6.4.10")
        lt("6.4.125", "6.4.125-r1")
        lt("6.4.125-r9", "6.4.125-r10")
        assertEquals(0, BundleVersions.compareVersions("6.4.125-r1", "6.4.125-r1"))
    }

    @Test fun builtOrdersRegardlessOfVersionString() {
        // Tools versions aren't comparable: "nmap-7.98+..." vs "nmap-7.95+..."; built decides.
        val older = m("nmap-7.98+hydra-9.5", 1000, 'a')
        val newer = m("nmap-7.95+hydra-9.6", 2000, 'b')
        assertTrue(BundleVersions.compare(newer, older) > 0)
        assertTrue(BundleVersions.isNewer(newer, older))
        assertFalse(BundleVersions.isNewer(older, newer))
    }

    @Test fun manifestWithoutBuiltIsOldest() {
        val legacyManifest = m("99.0", null, 'a')
        val withBuilt = m("1.0", 1, 'b')
        assertTrue(BundleVersions.compare(legacyManifest, withBuilt) < 0)
        assertFalse(BundleVersions.isNewer(legacyManifest, withBuilt))
        assertTrue(BundleVersions.isNewer(withBuilt, legacyManifest))
    }

    @Test fun bothWithoutBuiltFallBackToVersion() {
        assertTrue(BundleVersions.isNewer(m("6.4.126-r1", null, 'b', "msf"), m("6.4.125-r1", null, 'a', "msf")))
        assertFalse(BundleVersions.isNewer(m("6.4.124-r1", null, 'b', "msf"), m("6.4.125-r1", null, 'a', "msf")))
    }

    @Test fun equalBuiltFallsBackToVersionAndSameArchiveIsNeverNewer() {
        assertTrue(BundleVersions.isNewer(m("2", 5, 'b'), m("1", 5, 'a')))
        assertFalse(BundleVersions.isNewer(m("2", 9, 'a'), m("1", 5, 'a'))) // same sha
        assertTrue(BundleVersions.isNewer(m("1", 5), null)) // not installed / legacy
    }

    @Test fun apkVersusInstalledDecisionTable() {
        val apk = m("apk", 2000, 'a')
        fun install(installed: BundleManifest?, sentinels: Boolean = true) =
            BundleVersions.shouldInstallApkCopy(apk, installed, sentinels)
        assertTrue("fresh install", install(null, sentinels = false))
        assertTrue("legacy (no manifest)", install(null))
        assertTrue("broken install", install(apk, sentinels = false))
        assertFalse("same archive", install(m("apk-reformatted", 2000, 'a')))
        assertFalse("downloaded newer survives app update", install(m("dl", 3000, 'b')))
        assertTrue("APK newer than downloaded", install(m("dl", 1000, 'b')))
        assertTrue("installed manifest predates built", install(m("old", null, 'b')))
        assertTrue("same built, different archive, APK version not older", install(m("apk", 2000, 'b')))
    }

    @Test fun rollbackCheckHonoursForce() {
        val cand = m("6.4.124-r1", 1000, 'b', "msf")
        val installed = m("6.4.125-r1", 2000, 'a', "msf")
        val rejected = runCatching { CandidateVerifier.checkNotRollback(cand, installed, force = false) }
        assertTrue(rejected.exceptionOrNull() is BundleRejectedException)
        CandidateVerifier.checkNotRollback(cand, installed, force = true)
        CandidateVerifier.checkNotRollback(cand, null, force = false) // legacy / not installed
        val same = runCatching { CandidateVerifier.checkNotRollback(installed, installed, force = false) }
        assertTrue(same.exceptionOrNull() is BundleRejectedException)
    }
}

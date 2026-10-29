package org.csploit.strix.data.bundle

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException

class BundleInstallerTest {
    @get:Rule val tmp = TemporaryFolder()

    /** su is never available in tests: fail loudly if the installer reaches for it. */
    private val noSu = object : RootFs() {
        override fun su(command: String, timeoutSec: Long): Boolean = false
    }

    private val spec = BundleSpec(
        id = "msf",
        liveDirs = listOf("msf", "ruby"),
        mapPath = { name ->
            when {
                name.startsWith("metasploit-framework/") -> "msf/" + name.removePrefix("metasploit-framework/")
                name.startsWith("ruby-android/") -> "ruby/" + name.removePrefix("ruby-android/")
                else -> null
            }
        },
        postInstall = { staging -> File(staging, "msf/patched").writeText("yes") },
        sentinels = listOf("ruby/bin/ruby", "msf/msfconsole"),
    )

    private fun archive(tag: String) = TarFixture()
        .file("metasploit-framework/msfconsole", tag)
        .file("metasploit-framework/only-in-$tag", tag)
        .file("ruby-android/bin/ruby", tag)
        .build()

    private fun install(installer: BundleInstaller, a: ByteArray, json: String = TarFixture.manifestJson("msf", a)) {
        installer.stage(spec, a.inputStream(), BundleManifest.parse(json), json)
        installer.swap(spec)
    }

    @Test fun freshInstallThenUpgradeRemovesStaleFiles() {
        val files = tmp.newFolder("files")
        val installer = BundleInstaller(files, noSu)
        assertNull(installer.readInstalled(spec))

        val v1 = archive("v1")
        install(installer, v1, TarFixture.manifestJson("msf", v1, version = "1"))
        assertEquals("1", installer.readInstalled(spec)?.version)
        assertTrue(installer.sentinelsPresent(spec))
        assertEquals("yes", File(files, "msf/patched").readText())

        val v2 = archive("v2")
        install(installer, v2, TarFixture.manifestJson("msf", v2, version = "2"))
        assertEquals("2", installer.readInstalled(spec)?.version)
        assertEquals("v2", File(files, "msf/msfconsole").readText())
        assertFalse("stale file from v1 survived", File(files, "msf/only-in-v1").exists())
        assertEquals(setOf("msf", "ruby"), files.list()!!.toSet())
    }

    @Test fun sha256MismatchAbortsAndKeepsLiveInstall() {
        val files = tmp.newFolder("files")
        val installer = BundleInstaller(files, noSu)
        val v1 = archive("v1")
        install(installer, v1)

        val v2 = archive("v2")
        val badJson = TarFixture.manifestJson("msf", v2).replace(TarFixture.sha256(v2), "0".repeat(64))
        try {
            installer.stage(spec, v2.inputStream(), BundleManifest.parse(badJson), badJson)
            fail("expected sha256 mismatch")
        } catch (e: IOException) {
            assertTrue(e.message!!.contains("sha256"))
        }
        assertFalse(installer.hasStaged(spec))
        assertFalse(installer.stagingDir("msf").exists())
        assertEquals("v1", File(files, "msf/msfconsole").readText())
    }

    @Test fun sizeMismatchAborts() {
        val installer = BundleInstaller(tmp.newFolder("files"), noSu)
        val a = archive("v1")
        val json = TarFixture.manifestJson("msf", a).replace("\"size\":${a.size}", "\"size\":${a.size + 1}")
        val r = runCatching { installer.stage(spec, a.inputStream(), BundleManifest.parse(json), json) }
        assertTrue(r.exceptionOrNull()?.message!!.contains("size mismatch"))
    }

    @Test fun insufficientSpaceIsReported() {
        val installer = BundleInstaller(tmp.newFolder("files"), noSu)
        val a = archive("v1")
        val json = TarFixture.manifestJson("msf", a, unpacked = Long.MAX_VALUE / 2)
        val r = runCatching { installer.stage(spec, a.inputStream(), BundleManifest.parse(json), json) }
        assertTrue(r.exceptionOrNull() is InsufficientSpaceException)
    }

    @Test fun cleanupRestoresInterruptedSwapAndDropsStaging() {
        val files = tmp.newFolder("files")
        // Crash after moving msf/ aside but before installing the new one.
        File(files, ".old-msf/msf").mkdirs()
        File(files, ".old-msf/msf/msfconsole").writeText("old")
        File(files, "ruby/bin").mkdirs()
        File(files, ".staging-msf/msf").mkdirs()
        BundleInstaller(files, noSu).cleanupLeftovers()
        assertEquals("old", File(files, "msf/msfconsole").readText())
        assertFalse(File(files, ".old-msf").exists())
        assertFalse(File(files, ".staging-msf").exists())
    }

    @Test fun legacyInstallHasNoManifest() {
        val files = tmp.newFolder("files")
        File(files, "msf").mkdirs(); File(files, "msf/msfconsole").writeText("")
        File(files, "ruby/bin").mkdirs(); File(files, "ruby/bin/ruby").writeText("")
        val installer = BundleInstaller(files, noSu)
        assertTrue(installer.sentinelsPresent(spec))
        assertNull(installer.readInstalled(spec))
    }
}

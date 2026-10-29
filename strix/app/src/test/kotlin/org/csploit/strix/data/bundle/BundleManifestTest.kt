package org.csploit.strix.data.bundle

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BundleManifestTest {
    private val sha = "a".repeat(64)
    private fun json(extra: String = "", id: String = "msf", file: String = "ruby-msf-bundle.tar.gz.bin", format: Int = 1) =
        """{"format":$format,"id":"$id","version":"6.4.125-r1","file":"$file","sha256":"$sha","size":375581082,"unpacked":781000000,"minApp":2$extra}"""

    @Test fun parsesAllFields() {
        val m = BundleManifest.parse(json())
        assertEquals(BundleManifest(1, "msf", "6.4.125-r1", "ruby-msf-bundle.tar.gz.bin", sha, 375581082, 781000000, 2), m)
    }

    @Test fun builtIsOptionalAndAcceptsEpochOrIso() {
        assertEquals(null, BundleManifest.parse(json()).built)
        assertEquals(1776241523L, BundleManifest.parse(json(""","built":1776241523""")).built)
        assertEquals(1776241523L, BundleManifest.parse(json(""","built":"2026-04-15T08:25:23Z"""")).built)
        assertNull(BundleManifest.parseOrNull(json(""","built":"yesterday"""")))
        assertNull(BundleManifest.parseOrNull(json(""","built":0""")))
    }

    @Test fun ignoresUnknownFields() {
        assertEquals("msf", BundleManifest.parse(json(""","extra":"x"""")).id)
    }

    @Test fun uppercaseHashIsNormalized() {
        val m = BundleManifest.parse(json().replace(sha, "A".repeat(64)))
        assertEquals(sha, m.sha256)
    }

    @Test fun rejectsInvalid() {
        val bad = listOf(
            "not json",
            json(format = 2),
            json(file = "../evil"),
            json(file = "a/b"),
            json(id = "a b"),
            json().replace(sha, "xyz"),
            json().replace("\"size\":375581082", "\"size\":0"),
            json().replace(",\"minApp\":2", ""),
        )
        for (b in bad) assertNull(b, BundleManifest.parseOrNull(b))
    }

    @Test fun shippedToolsManifestParses() {
        val f = listOf("src/main/assets/tools-bundle.json", "app/src/main/assets/tools-bundle.json")
            .map { java.io.File(it) }.first { it.exists() }
        val m = BundleManifest.parse(f.readText())
        assertEquals("tools", m.id)
        assertEquals("tools-bundle.tar.gz.bin", m.file)
        assertTrue("shipped tools manifest must carry built", (m.built ?: 0) > 0)
    }

    @Test fun sameContentComparesIdAndHash() {
        val a = BundleManifest.parse(json())
        assertTrue(a.sameContentAs(a.copy(version = "other")))
        assertFalse(a.sameContentAs(a.copy(sha256 = "b".repeat(64))))
        assertFalse(a.sameContentAs(null))
    }
}

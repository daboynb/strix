package org.csploit.strix.data.bundle

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

class GitHubReleasesTest {
    private fun asset(name: String, size: Long = 10) =
        """{"name":"$name","size":$size,"browser_download_url":"https://github.com/dl/$name"}"""

    private fun release(tag: String, created: String, draft: Boolean = false, assets: List<String>) =
        """{"tag_name":"$tag","created_at":"$created","draft":$draft,"assets":[${assets.joinToString(",")}]}"""

    private val fullAssets = listOf(
        asset("ruby-msf-bundle.tar.gz.bin", 100),
        asset("ruby-msf-bundle.tar.gz.bin.json"),
        asset("ruby-msf-bundle.tar.gz.bin.json.sig"),
    )

    @Test fun picksNewestNonDraftWithManifest() {
        val json = "[" + listOf(
            release("bundles-msf-6.4.125-r1", "2026-10-01T00:00:00Z", assets = fullAssets),
            release("bundles-msf-6.4.126-r1", "2026-10-20T00:00:00Z", assets = fullAssets),
            release("bundles-msf-6.4.127-r1", "2026-10-25T00:00:00Z", draft = true, assets = fullAssets),
            release("bundles-tools-r9", "2026-10-28T00:00:00Z", assets = fullAssets),
            release("bundles-msf-6.4.128-r1", "2026-10-27T00:00:00Z", assets = fullAssets.take(2)), // no .sig
            release("v0.2.0", "2026-10-29T00:00:00Z", assets = emptyList()),
        ).joinToString(",") + "]"
        val r = GitHubReleases.pickLatest(json, GitHubReleases.MSF_TAG_PREFIX)!!
        assertEquals("bundles-msf-6.4.126-r1", r.tag)
        assertEquals("ruby-msf-bundle.tar.gz.bin.json", r.manifest.name)
        assertEquals("ruby-msf-bundle.tar.gz.bin.json.sig", r.signature.name)
        assertEquals(100L, r.asset("ruby-msf-bundle.tar.gz.bin")!!.size)
    }

    @Test fun oneReleasesListServesBothBundles() {
        val tools = listOf(
            asset("tools-bundle.tar.gz.bin", 22),
            asset("tools-bundle.json"),
            asset("tools-bundle.json.sig"),
        )
        val json = "[" + listOf(
            release("bundles-tools-r2", "2026-10-02T00:00:00Z", assets = tools),
            release("bundles-msf-6.4.125-r1", "2026-10-03T00:00:00Z", assets = fullAssets),
            release("bundles-tools-r3", "2026-10-04T00:00:00Z", assets = tools),
            release("bundles-tools-r4", "2026-10-05T00:00:00Z", draft = true, assets = tools),
        ).joinToString(",") + "]"
        val t = GitHubReleases.pickLatest(json, GitHubReleases.TOOLS_TAG_PREFIX)!!
        val m = GitHubReleases.pickLatest(json, GitHubReleases.MSF_TAG_PREFIX)!!
        assertEquals("bundles-tools-r3", t.tag)
        assertEquals("tools-bundle.json", t.manifest.name)
        assertEquals("tools-bundle.json.sig", t.signature.name)
        assertEquals("bundles-msf-6.4.125-r1", m.tag)
        assertEquals("ruby-msf-bundle.tar.gz.bin.json", m.manifest.name)
    }

    @Test fun noReleases() {
        assertNull(GitHubReleases.pickLatest("[]", GitHubReleases.MSF_TAG_PREFIX))
    }

    @Test fun candidateVerification() {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val manifest = """{"format":1,"id":"msf","version":"6.4.126-r1","file":"ruby-msf-bundle.tar.gz.bin","sha256":"${"c".repeat(64)}","size":100,"unpacked":200,"minApp":3}""".toByteArray()
        val sig = Signature.getInstance("SHA256withECDSA").run { initSign(kp.private); update(manifest); sign() }
        val rel = GitHubReleases.pickLatest("[" + release("bundles-msf-x", "2026-10-01T00:00:00Z", assets = fullAssets) + "]", "bundles-msf-")!!

        val ok = CandidateVerifier.verify(rel, manifest, sig, "msf", appVersionCode = 3, key = kp.public)
        assertEquals("6.4.126-r1", ok.manifest.version)

        fun rejected(block: () -> Unit) = assertTrue(runCatching(block).exceptionOrNull() is BundleRejectedException)
        rejected { CandidateVerifier.verify(rel, manifest, sig, "msf", appVersionCode = 2, key = kp.public) } // minApp
        rejected { CandidateVerifier.verify(rel, manifest, sig, "tools", appVersionCode = 3, key = kp.public) } // id
        rejected { CandidateVerifier.verify(rel, manifest, sig, "msf", appVersionCode = 3) } // pinned key didn't sign
        val tampered = String(manifest).replace("\"size\":100", "\"size\":101").toByteArray()
        rejected { CandidateVerifier.verify(rel, tampered, sig, "msf", appVersionCode = 3, key = kp.public) }
    }
}

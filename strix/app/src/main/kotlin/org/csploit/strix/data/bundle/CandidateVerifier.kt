package org.csploit.strix.data.bundle

import java.io.IOException
import java.security.PublicKey

class BundleRejectedException(message: String) : IOException(message)

/** Checks everything about a release candidate that can be checked before downloading the archive. */
internal object CandidateVerifier {

    /**
     * Verify [manifestBytes] against [sigBytes] with [key] FIRST, then parse it
     * and check id, archive asset presence/size and the app versionCode.
     */
    fun verify(
        release: BundleRelease,
        manifestBytes: ByteArray,
        sigBytes: ByteArray,
        expectedId: String,
        appVersionCode: Long,
        key: PublicKey = SignatureVerifier.pinnedKey,
    ): VerifiedCandidate {
        if (!SignatureVerifier.verify(manifestBytes, sigBytes, key)) {
            throw BundleRejectedException("manifest signature is invalid (${release.manifest.name})")
        }
        val json = String(manifestBytes, Charsets.UTF_8)
        val manifest = try {
            BundleManifest.parse(json)
        } catch (e: IllegalArgumentException) {
            throw BundleRejectedException("bad manifest: ${e.message}")
        }
        if (manifest.id != expectedId) throw BundleRejectedException("manifest is for '${manifest.id}', expected '$expectedId'")
        val archive = release.asset(manifest.file)
            ?: throw BundleRejectedException("release ${release.tag} has no asset ${manifest.file}")
        if (archive.size > 0 && archive.size != manifest.size) {
            throw BundleRejectedException("asset size ${archive.size} != manifest size ${manifest.size}")
        }
        if (manifest.minApp > appVersionCode) {
            throw BundleRejectedException("Metasploit ${manifest.version} needs a newer Strix (app build ${manifest.minApp}+)")
        }
        return VerifiedCandidate(release, manifest, json, archive)
    }

    /**
     * Rollback protection: refuse anything not newer than [installed]
     * (null = not installed / legacy) unless [force]. Ordered by `built`.
     */
    fun checkNotRollback(candidate: BundleManifest, installed: BundleManifest?, force: Boolean) {
        if (force) return
        if (!BundleVersions.isNewer(candidate, installed)) {
            throw BundleRejectedException("${candidate.id} ${candidate.version} is not newer than the installed ${installed?.version}")
        }
    }
}

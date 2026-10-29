package org.csploit.strix.data.bundle

import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.csploit.strix.data.AppSettings
import java.io.File

/**
 * The resolve / download / verify / stage / swap steps of a [BundleChannel],
 * publishing progress into the channel's [_state].
 */
internal class BundleInstallPipeline(
    private val id: String,
    private val tagPrefix: String,
    private val spec: BundleSpec,
    private val installer: BundleInstaller,
    private val downloader: BundleDownloader,
    private val settings: AppSettings,
    private val env: BundleEnv,
    private val downloadsDir: File,
    private val hooks: BundleHooks,
    private val _state: MutableStateFlow<BundleState>,
    private val refreshInstalled: () -> Unit,
) {
    companion object {
        private const val MAX_MANIFEST_BYTES = 64 * 1024
    }

    /** Latest release for [tagPrefix] with a valid signed manifest, or null if none exists. */
    fun resolveCandidate(releasesJson: String): VerifiedCandidate? {
        val release = GitHubReleases.pickLatest(releasesJson, tagPrefix) ?: return null
        val manifestBytes = downloader.fetchBytes(release.manifest.url, MAX_MANIFEST_BYTES)
        val sigBytes = downloader.fetchBytes(release.signature.url, MAX_MANIFEST_BYTES)
        return CandidateVerifier.verify(release, manifestBytes, sigBytes, spec.id, env.appVersionCode())
    }

    suspend fun runInstall(force: Boolean) {
        val label = _state.value.label
        if (settings.bundleWifiOnly && !env.isOnWifi()) {
            throw BundleRejectedException("Not on Wi-Fi (\"Wi-Fi only downloads\" is enabled in Settings)")
        }
        _state.update { it.copy(op = BundleOp.Checking, message = null) }
        val c = resolveCandidate(env.fetchReleasesJson())
            ?: throw BundleRejectedException("No $label bundle has been published yet")
        CandidateVerifier.checkNotRollback(c.manifest, hooks.installedManifest(), force)

        val dest = File(downloadsDir, c.manifest.file)
        // Drop downloads of other versions/bundles of this channel; keep this one's .part to resume.
        downloadsDir.listFiles()
            ?.filter { it.name.startsWith(c.manifest.file) && it.name != dest.name && it.name != dest.name + ".part" }
            ?.forEach { it.delete() }
        val have = if (dest.isFile) dest.length() else File(dest.path + ".part").length()
        installer.checkFreeSpace((c.manifest.size - have).coerceAtLeast(0) + installer.requiredSpace(c.manifest))

        val archive = if (dest.isFile && dest.length() == c.manifest.size) dest else {
            _state.update { it.copy(op = BundleOp.Downloading(have, c.manifest.size)) }
            downloader.download(c.archive.url, dest, c.manifest.size, c.manifest.sha256) { done, total ->
                _state.update { it.copy(op = if (done >= total) BundleOp.Verifying else BundleOp.Downloading(done, total)) }
            }
        }

        _state.update { it.copy(op = BundleOp.Installing(0, c.manifest.size)) }
        val ctx = currentCoroutineContext()
        withLockIfAny {
            archive.inputStream().use { input ->
                installer.stage(spec, input, c.manifest, c.manifestJson) { bytes, _ ->
                    ctx.ensureActive()
                    _state.update { it.copy(op = BundleOp.Installing(bytes, c.manifest.size)) }
                }
            }
        }
        // The staged tree carries its own verified copy; the archive is no longer needed.
        archive.delete()
        trySwap()
    }

    suspend fun trySwap() {
        if (!installer.hasStaged(spec)) {
            _state.update { it.copy(op = BundleOp.Error("The staged update was lost (app restarted); download it again")) }
            return
        }
        val version = installer.readStagedVersion(spec) ?: "?"
        hooks.swapBlocker()?.let { reason ->
            _state.update { it.copy(op = BundleOp.PendingSwap(version, reason)) }
            return
        }
        _state.update { it.copy(op = BundleOp.Installing(1, 1)) }
        try {
            hooks.beforeSwap()
            // Renames only: never leave the swap half-done because of a cancel.
            withContext(NonCancellable) { withLockIfAny { installer.swap(spec) } }
        } finally {
            withContext(NonCancellable) { hooks.afterSwap() }
        }
        settings.setAvailableManifest(id, null)
        refreshInstalled()
        _state.update { it.copy(op = BundleOp.Idle, message = "${it.label} $version installed") }
    }

    suspend fun <T> withLockIfAny(block: suspend () -> T): T {
        val lock = hooks.lock ?: return block()
        return lock.withLock { block() }
    }
}

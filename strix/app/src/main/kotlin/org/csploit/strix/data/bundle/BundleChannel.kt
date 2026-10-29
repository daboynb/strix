package org.csploit.strix.data.bundle

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.csploit.strix.core.Logger
import org.csploit.strix.data.AppSettings
import java.io.File

/**
 * Download / verify / install / swap pipeline for ONE bundle published as
 * GitHub releases with tag prefix [tagPrefix]. Shared by tools and msf; the
 * bundle-specific parts come from [hooks]. Never downloads on its own.
 */
class BundleChannel(
    val id: String,
    label: String,
    val tagPrefix: String,
    private val spec: BundleSpec,
    private val installer: BundleInstaller,
    private val downloader: BundleDownloader,
    private val settings: AppSettings,
    private val env: BundleEnv,
    private val downloadsDir: File,
    private val scope: CoroutineScope,
    private val hooks: BundleHooks,
) {
    companion object {
        private const val MAX_MANIFEST_BYTES = 64 * 1024
    }

    private val _state = MutableStateFlow(BundleState(label))
    val state: StateFlow<BundleState> = _state.asStateFlow()

    private var job: Job? = null

    fun refreshInstalled() {
        val installed = hooks.installedManifest()
        val available = BundleManifest.parseOrNull(settings.availableManifest(id))
            ?.takeIf { BundleVersions.isNewer(it, installed) }
        _state.update {
            it.copy(
                installedVersion = hooks.installedLabel(),
                source = hooks.source(),
                availableVersion = available?.version,
                downloadSize = available?.size ?: it.downloadSize,
                lastCheckMs = settings.bundleLastCheckMs,
            )
        }
    }

    /** Download + install the latest release. [force] allows reinstalling the same or an older one. */
    fun install(force: Boolean = false) = launchOp { runInstall(force) }

    /** Retry the swap of an already staged bundle (after the user stopped what was using it). */
    fun applyPending() = launchOp { trySwap() }

    /**
     * Cancel the running download/install (the partial download is kept for
     * resume, a half-staged tree is deleted by the installer) or drop a staged
     * update that is waiting for its swap.
     */
    fun cancel() {
        val running = synchronized(this) { job?.takeIf { it.isActive } }
        if (running != null) {
            running.cancel()
        } else if (_state.value.op is BundleOp.PendingSwap) {
            scope.launch { withLockIfAny { installer.discardStaged(spec) } }
        }
        _state.update { it.copy(op = BundleOp.Idle) }
    }

    fun dismissMessage() = _state.update {
        it.copy(message = null, op = if (it.op is BundleOp.Error) BundleOp.Idle else it.op)
    }

    internal fun markChecking() {
        if (!_state.value.op.busy) _state.update { it.copy(op = BundleOp.Checking, message = null) }
    }

    /** Apply a failed (non-silent) check. */
    internal fun checkFailed(message: String) {
        if (_state.value.op is BundleOp.Checking) _state.update { it.copy(op = BundleOp.Error(message)) }
    }

    /**
     * Resolve this bundle's candidate from an already fetched releases list
     * (so one API call serves every channel) and publish the result.
     * Silent checks never surface errors or messages.
     */
    internal fun applyCheck(releasesJson: String, silent: Boolean) {
        val candidate = try {
            resolveCandidate(releasesJson)
        } catch (e: Exception) {
            Logger.warning("BundleChannel[$id]: check failed: ${e.message}")
            if (!silent) checkFailed(e.message ?: e.javaClass.simpleName)
            return
        }
        val installed = hooks.installedManifest()
        val newer = candidate?.manifest?.takeIf { BundleVersions.isNewer(it, installed) }
        settings.setAvailableManifest(id, newer?.let { candidate.manifestJson })
        Logger.info("BundleChannel[$id]: latest=${candidate?.manifest?.version} installed=${installed?.version}")
        _state.update {
            it.copy(
                installedVersion = hooks.installedLabel(),
                source = hooks.source(),
                availableVersion = newer?.version,
                downloadSize = candidate?.manifest?.size ?: it.downloadSize,
                lastCheckMs = settings.bundleLastCheckMs,
                op = if (it.op is BundleOp.Checking) BundleOp.Idle else it.op,
                message = when {
                    silent -> it.message
                    candidate == null -> "No ${it.label} bundle has been published yet"
                    newer == null -> "${it.label}: already up to date"
                    else -> null
                },
            )
        }
    }

    private fun launchOp(block: suspend () -> Unit) {
        synchronized(this) {
            if (job?.isActive == true) return
            job = scope.launch {
                try {
                    block()
                } catch (e: CancellationException) {
                    _state.update { it.copy(op = BundleOp.Idle) }
                    throw e
                } catch (e: Exception) {
                    Logger.error("BundleChannel[$id]: ${e.javaClass.simpleName}: ${e.message}")
                    _state.update { it.copy(op = BundleOp.Error(e.message ?: e.javaClass.simpleName)) }
                }
            }
        }
    }

    /** Latest release for [tagPrefix] with a valid signed manifest, or null if none exists. */
    private fun resolveCandidate(releasesJson: String): VerifiedCandidate? {
        val release = GitHubReleases.pickLatest(releasesJson, tagPrefix) ?: return null
        val manifestBytes = downloader.fetchBytes(release.manifest.url, MAX_MANIFEST_BYTES)
        val sigBytes = downloader.fetchBytes(release.signature.url, MAX_MANIFEST_BYTES)
        return CandidateVerifier.verify(release, manifestBytes, sigBytes, spec.id, env.appVersionCode())
    }

    private suspend fun runInstall(force: Boolean) {
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

    private suspend fun trySwap() {
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

    private suspend fun <T> withLockIfAny(block: suspend () -> T): T {
        val lock = hooks.lock ?: return block()
        return lock.withLock { block() }
    }
}

package org.csploit.strix.data.bundle

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
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
    private val _state = MutableStateFlow(BundleState(label))
    val state: StateFlow<BundleState> = _state.asStateFlow()

    private val pipeline = BundleInstallPipeline(
        id, tagPrefix, spec, installer, downloader, settings, env, downloadsDir, hooks, _state, ::refreshInstalled,
    )

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
    fun install(force: Boolean = false) = launchOp { pipeline.runInstall(force) }

    /** Retry the swap of an already staged bundle (after the user stopped what was using it). */
    fun applyPending() = launchOp { pipeline.trySwap() }

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
            scope.launch { pipeline.withLockIfAny { installer.discardStaged(spec) } }
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
            pipeline.resolveCandidate(releasesJson)
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
}

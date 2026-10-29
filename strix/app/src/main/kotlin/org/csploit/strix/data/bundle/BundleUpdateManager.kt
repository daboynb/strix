package org.csploit.strix.data.bundle

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.csploit.strix.core.Logger
import org.csploit.strix.core.ScanRegistry
import org.csploit.strix.data.AppSettings
import org.csploit.strix.data.DaemonState
import org.csploit.strix.data.MsfDaemon
import org.csploit.strix.data.ToolManager
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Runtime updates of both native bundles from GitHub releases. One releases
 * API call (60/h unauthenticated) serves the check of every channel.
 */
@Singleton
class BundleUpdateManager @Inject constructor(
    @ApplicationContext private val context: Context,
    private val toolManager: ToolManager,
    private val msfDaemon: MsfDaemon,
    private val scanRegistry: ScanRegistry,
    private val appSettings: AppSettings,
    private val downloader: BundleDownloader,
) {
    companion object {
        private const val CHECK_INTERVAL_MS = 24L * 60 * 60 * 1000
        private const val MAX_API_BYTES = 2 * 1024 * 1024
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val rootFs = RootFs()

    private val env = object : BundleEnv {
        override fun isOnWifi(): Boolean {
            val cm = context.getSystemService(ConnectivityManager::class.java) ?: return false
            val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return false
            return caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
        }

        override fun appVersionCode(): Long =
            context.packageManager.getPackageInfo(context.packageName, 0).longVersionCode

        override fun fetchReleasesJson(): String = String(
            downloader.fetchBytes(GitHubReleases.RELEASES_URL, MAX_API_BYTES, "application/vnd.github+json"),
            Charsets.UTF_8,
        )
    }

    private fun channel(id: String, label: String, prefix: String, spec: BundleSpec, hooks: BundleHooks) =
        BundleChannel(
            id, label, prefix, spec, toolManager.installer, downloader, appSettings, env,
            File(context.filesDir, "downloads"), scope, hooks,
        )

    val msf: BundleChannel = channel(
        "msf", "Metasploit", GitHubReleases.MSF_TAG_PREFIX, toolManager.msfSpec,
        BundleHooks(
            installedManifest = { toolManager.installedManifest(toolManager.msfSpec) },
            installedLabel = { toolManager.installedMsfVersion() },
            swapBlocker = {
                val d = msfDaemon.state.value
                when {
                    d != DaemonState.STOPPED && d != DaemonState.FAILED -> "Update pending: stop Metasploit first."
                    scanRegistry.activeTasks.value.isNotEmpty() -> "Update pending: stop running scans first."
                    else -> null
                }
            },
            beforeSwap = { msfDaemon.beginMaintenance() },
            afterSwap = { msfDaemon.endMaintenance() },
        ),
    )

    val tools: BundleChannel = channel(
        "tools", "Tools", GitHubReleases.TOOLS_TAG_PREFIX, toolManager.toolsSpec,
        BundleHooks(
            installedManifest = { toolManager.installedManifest(toolManager.toolsSpec) },
            installedLabel = { toolManager.installedToolsVersion() },
            source = { toolManager.toolsSource() },
            swapBlocker = {
                when {
                    scanRegistry.activeTasks.value.isNotEmpty() -> "Update pending: stop running scans and attacks first."
                    toolProcessesRunning() -> "Update pending: a tool (nmap, hydra, ettercap, ...) is still running."
                    else -> null
                }
            },
            lock = toolManager.toolsLock,
        ),
    )

    val channels: List<BundleChannel> = listOf(tools, msf)

    private val _checking = MutableStateFlow(false)
    val checking: StateFlow<Boolean> = _checking.asStateFlow()
    private var checkJob: Job? = null

    init {
        refreshInstalled()
    }

    fun refreshInstalled() = channels.forEach { it.refreshInstalled() }

    /** Daily automatic check (app start). Silent; respects the Wi-Fi only setting; never downloads. */
    fun autoCheckIfDue() {
        val due = System.currentTimeMillis() - appSettings.bundleLastCheckMs >= CHECK_INTERVAL_MS
        if (!due || (appSettings.bundleWifiOnly && !env.isOnWifi())) return
        runCheck(silent = true)
    }

    fun checkForUpdates() = runCheck(silent = false)

    private fun runCheck(silent: Boolean) {
        synchronized(this) {
            if (checkJob?.isActive == true) return
            checkJob = scope.launch {
                _checking.value = true
                if (!silent) channels.forEach { it.markChecking() }
                try {
                    val json = try {
                        env.fetchReleasesJson()
                    } catch (e: Exception) {
                        Logger.warning("BundleUpdateManager: releases check failed: ${e.message}")
                        if (!silent) channels.forEach { it.checkFailed("Update check failed: ${e.message}") }
                        return@launch
                    }
                    appSettings.bundleLastCheckMs = System.currentTimeMillis()
                    channels.forEach { it.applyCheck(json, silent) }
                } finally {
                    _checking.value = false
                }
            }
        }
    }

    /**
     * True if any process runs a binary from the tools dir (MITM, hydra,
     * tcpdump, an orphan from a previous run...). Blocking su call.
     */
    private fun toolProcessesRunning(): Boolean {
        val path = toolManager.toolsPath
        // "[/]data/..." matches the path but not this pgrep's own `sh -c` command line.
        val pattern = "[" + path.first() + "]" + path.drop(1)
        return rootFs.su("pgrep -f '$pattern' >/dev/null", timeoutSec = 15)
    }
}

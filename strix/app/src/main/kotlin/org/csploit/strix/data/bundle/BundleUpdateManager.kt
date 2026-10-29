package org.csploit.strix.data.bundle

import android.content.Context
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
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val rootFs = RootFs()

    private val env: BundleEnv = AndroidBundleEnv(context, downloader)

    private fun channel(id: String, label: String, prefix: String, spec: BundleSpec, hooks: BundleHooks) =
        BundleChannel(
            id, label, prefix, spec, toolManager.installer, downloader, appSettings, env,
            File(context.filesDir, "downloads"), scope, hooks,
        )

    val msf: BundleChannel = channel(
        "msf", "Metasploit", GitHubReleases.MSF_TAG_PREFIX, toolManager.msfSpec,
        msfHooks(toolManager, msfDaemon, scanRegistry),
    )

    val tools: BundleChannel = channel(
        "tools", "Tools", GitHubReleases.TOOLS_TAG_PREFIX, toolManager.toolsSpec,
        toolsHooks(toolManager, scanRegistry, rootFs),
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
}

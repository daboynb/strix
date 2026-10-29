package org.csploit.strix.data.bundle

import org.csploit.strix.core.ScanRegistry
import org.csploit.strix.data.DaemonState
import org.csploit.strix.data.MsfDaemon
import org.csploit.strix.data.ToolManager

// Bundle-specific behaviour plugged into the generic [BundleChannel]s of [BundleUpdateManager].

internal fun msfHooks(toolManager: ToolManager, msfDaemon: MsfDaemon, scanRegistry: ScanRegistry) = BundleHooks(
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
)

internal fun toolsHooks(toolManager: ToolManager, scanRegistry: ScanRegistry, rootFs: RootFs) = BundleHooks(
    installedManifest = { toolManager.installedManifest(toolManager.toolsSpec) },
    installedLabel = { toolManager.installedToolsVersion() },
    source = { toolManager.toolsSource() },
    swapBlocker = {
        when {
            scanRegistry.activeTasks.value.isNotEmpty() -> "Update pending: stop running scans and attacks first."
            toolProcessesRunning(toolManager, rootFs) -> "Update pending: a tool (nmap, hydra, ettercap, ...) is still running."
            else -> null
        }
    },
    lock = toolManager.toolsLock,
)

/**
 * True if any process runs a binary from the tools dir (MITM, hydra,
 * tcpdump, an orphan from a previous run...). Blocking su call.
 */
private fun toolProcessesRunning(toolManager: ToolManager, rootFs: RootFs): Boolean {
    val path = toolManager.toolsPath
    // "[/]data/..." matches the path but not this pgrep's own `sh -c` command line.
    val pattern = "[" + path.first() + "]" + path.drop(1)
    return rootFs.su("pgrep -f '$pattern' >/dev/null", timeoutSec = 15)
}

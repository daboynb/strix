package org.csploit.strix.data

import org.csploit.strix.core.Logger
import org.csploit.strix.core.shellQuote
import org.csploit.strix.data.bundle.RootFs
import java.io.File

/**
 * msfrpcd used to run with HOME=ruby/, so ~/.msf4 (database config,
 * history, loot) lives inside the bundle dir and is root-owned. Move it to
 * msf-home/ once; blocking, call on Dispatchers.IO.
 */
internal fun migrateMsfHome(toolManager: ToolManager, rootFs: RootFs) {
    val home = File(toolManager.msfHomePath)
    home.mkdirs()
    val legacy = File(toolManager.rubyPath, ".msf4")
    if (!rootFs.exists(legacy)) return
    val target = File(home, ".msf4")
    if (rootFs.exists(target)) return // already migrated; the stale copy goes away with ruby/
    val ok = rootFs.su(
        "cp -a ${shellQuote(legacy.absolutePath)} ${shellQuote(home.absolutePath)}/ && " +
            "rm -rf ${shellQuote(legacy.absolutePath)}",
    )
    Logger.info("MsfDaemon: migrated ~/.msf4 to ${home.absolutePath}: $ok")
}

/** Blocking (su + waitFor + sleep): call only from Dispatchers.IO. */
internal fun killOrphanedMsfrpcd() {
    try {
        val pb = ProcessBuilder("su", "-c", "pkill -f msfrpcd")
        val p = pb.start()
        p.waitFor()
        // Small delay to let the port be released
        Thread.sleep(500)
        Logger.info("MsfDaemon: killed orphaned msfrpcd processes")
    } catch (e: Exception) {
        Logger.debug("MsfDaemon: no orphaned processes to kill: ${e.message}")
    }
}

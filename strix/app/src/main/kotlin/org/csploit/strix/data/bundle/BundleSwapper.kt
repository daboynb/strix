package org.csploit.strix.data.bundle

import org.csploit.strix.core.Logger
import java.io.File
import java.io.IOException

internal const val STAGING_PREFIX = ".staging-"
internal const val OLD_PREFIX = ".old-"

/**
 * The rename half of [BundleInstaller]: live dirs → `.old-<id>`, staging →
 * live, delete `.old-<id>`, plus the repair of a swap interrupted by a crash.
 */
internal class BundleSwapper(private val filesDir: File, private val fs: RootFs) {

    private fun oldDir(id: String) = File(filesDir, OLD_PREFIX + id)

    /**
     * Finish or roll back an interrupted swap and drop half-extracted staging
     * dirs. If a live dir is missing but its `.old-` copy survived, the old
     * copy is restored.
     */
    fun repairLeftovers() {
        filesDir.listFiles()?.forEach { f ->
            when {
                f.name.startsWith(OLD_PREFIX) -> {
                    f.listFiles()?.forEach { saved ->
                        val live = File(filesDir, saved.name)
                        if (!fs.exists(live)) {
                            Logger.warning("BundleInstaller: restoring ${saved.name} from interrupted swap")
                            fs.move(saved, live)
                        }
                    }
                    fs.deleteTree(f)
                }
                f.name.startsWith(STAGING_PREFIX) -> fs.deleteTree(f)
            }
        }
    }

    /** Replace the live dirs of [spec] with the ones in [staging]. Rolls back on failure. */
    fun swap(spec: BundleSpec, staging: File) {
        val old = oldDir(spec.id)
        if (!fs.deleteTree(old)) throw IOException("cannot clear $old")
        old.mkdirs()
        val installed = mutableListOf<String>()
        try {
            for (d in spec.liveDirs) {
                val live = File(filesDir, d)
                if (fs.exists(live) && !fs.move(live, File(old, d))) throw IOException("cannot move $live aside")
            }
            for (d in spec.liveDirs) {
                if (!fs.move(File(staging, d), File(filesDir, d))) throw IOException("cannot install $d")
                installed += d
            }
        } catch (e: IOException) {
            Logger.error("BundleInstaller: swap of ${spec.id} failed, rolling back: ${e.message}")
            for (d in spec.liveDirs) {
                val live = File(filesDir, d)
                val saved = File(old, d)
                if (d in installed || fs.exists(saved)) fs.deleteTree(live)
                if (fs.exists(saved)) fs.move(saved, live)
            }
            throw e
        }
        if (!fs.deleteTree(old)) Logger.warning("BundleInstaller: could not delete $old (will retry next start)")
        fs.deleteTree(staging)
        Logger.info("BundleInstaller: ${spec.id} swapped in")
    }
}

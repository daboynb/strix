package org.csploit.strix.data.bundle

import java.io.File
import java.io.IOException
import java.io.InputStream

class InsufficientSpaceException(val needed: Long, val available: Long) :
    IOException("Not enough free space: need ${needed / 1_048_576} MB, have ${available / 1_048_576} MB")

/**
 * Generic bundle installer. Two phases:
 *  - [stage]: verify + extract into `filesDir/.staging-<id>`, run the bundle's
 *    patches, write `.bundle-version`. Live files are untouched.
 *  - [swap]: live dirs → `.old-<id>`, staging → live, delete `.old-<id>`.
 * [cleanupLeftovers] repairs a swap interrupted by a crash.
 */
class BundleInstaller(private val filesDir: File, private val fs: RootFs = RootFs()) {

    companion object {
        const val VERSION_FILE = ".bundle-version"
        const val SPACE_FACTOR = 1.15
    }

    private val swapper = BundleSwapper(filesDir, fs)
    private var cleaned = false

    fun stagingDir(id: String) = File(filesDir, STAGING_PREFIX + id)

    fun readInstalledJson(spec: BundleSpec): String? =
        File(filesDir, "${spec.primaryDir}/$VERSION_FILE").takeIf { it.isFile }?.readText()

    fun readInstalled(spec: BundleSpec): BundleManifest? = BundleManifest.parseOrNull(readInstalledJson(spec))

    fun sentinelsPresent(spec: BundleSpec): Boolean = spec.sentinels.all { File(filesDir, it).exists() }

    fun readStagedVersion(spec: BundleSpec): String? = BundleManifest.parseOrNull(
        File(stagingDir(spec.id), "${spec.primaryDir}/$VERSION_FILE").takeIf { it.isFile }?.readText(),
    )?.version

    fun hasStaged(spec: BundleSpec): Boolean = File(stagingDir(spec.id), "${spec.primaryDir}/$VERSION_FILE").isFile

    /** Bytes needed on filesDir to stage [m] (old + new coexist until the swap). */
    fun requiredSpace(m: BundleManifest): Long = (m.unpacked * SPACE_FACTOR).toLong()

    fun checkFreeSpace(needed: Long) {
        val available = filesDir.usableSpace
        if (available < needed) throw InsufficientSpaceException(needed, available)
    }

    /**
     * Once per process: finish or roll back an interrupted swap and drop
     * half-extracted staging dirs. If a live dir is missing but its `.old-`
     * copy survived, the old copy is restored.
     */
    @Synchronized
    fun cleanupLeftovers() {
        if (cleaned) return
        cleaned = true
        swapper.repairLeftovers()
    }

    /**
     * Extract [gzStream] (the bundle archive) into the staging dir, verifying
     * its size and sha256 against [manifest] while streaming. Returns the staging dir.
     * [onProgress] gets (compressed bytes read, files extracted) and may throw
     * CancellationException to abort; staging is deleted on any failure.
     */
    fun stage(
        spec: BundleSpec,
        gzStream: InputStream,
        manifest: BundleManifest,
        manifestJson: String,
        onProgress: (Long, Int) -> Unit = { _, _ -> },
    ): File {
        require(manifest.id == spec.id) { "manifest id ${manifest.id} != ${spec.id}" }
        checkFreeSpace(requiredSpace(manifest))
        val staging = stagingDir(spec.id)
        if (!fs.deleteTree(staging)) throw IOException("cannot clear $staging")
        staging.mkdirs()
        try {
            val hashed = HashingStream(gzStream)
            SafeTarExtractor.extract(
                gzStream = NonClosing(hashed),
                root = staging,
                mapPath = { name ->
                    spec.mapPath(name)?.also { mapped ->
                        require(spec.liveDirs.any { mapped == it || mapped.startsWith("$it/") }) {
                            "entry $name maps outside the bundle dirs"
                        }
                    }
                },
                onEntry = { count, _ -> if (count % 100 == 0) onProgress(hashed.count, count) },
            )
            // Hash must cover the whole file, including what tar/gzip left unread.
            val sink = ByteArray(65536)
            while (hashed.read(sink) >= 0) { /* drain */ }
            if (hashed.count != manifest.size) throw IOException("size mismatch: ${hashed.count} != ${manifest.size}")
            val actual = hashed.hexDigest()
            if (actual != manifest.sha256) throw IOException("sha256 mismatch: $actual")
            spec.liveDirs.forEach { if (!File(staging, it).isDirectory) throw IOException("bundle has no $it/") }
            spec.postInstall(staging)
            File(staging, "${spec.primaryDir}/$VERSION_FILE").writeText(manifestJson)
            onProgress(hashed.count, -1)
            return staging
        } catch (t: Throwable) {
            fs.deleteTree(staging)
            throw t
        }
    }

    /** Replace the live dirs with the staged ones. Rolls back on failure. */
    fun swap(spec: BundleSpec) {
        val staging = stagingDir(spec.id)
        if (!hasStaged(spec)) throw IOException("nothing staged for ${spec.id}")
        swapper.swap(spec, staging)
    }

    fun discardStaged(spec: BundleSpec) {
        fs.deleteTree(stagingDir(spec.id))
    }
}

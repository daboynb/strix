package org.csploit.strix.data.bundle

import java.io.File

/**
 * How one bundle is laid out under filesDir.
 *
 * @param liveDirs top-level directories under filesDir owned by the bundle;
 *   the first one holds `.bundle-version`. They are swapped together.
 * @param mapPath maps an archive entry name to a path relative to the staging
 *   root (which must start with one of [liveDirs]), or null to skip it.
 * @param postInstall patches run on the staging root before the swap; must be
 *   idempotent and must only write paths that are valid after the swap
 *   (relative symlinks, no staging-absolute paths). Throwing aborts the install.
 * @param sentinels paths (relative to filesDir) that must exist for the
 *   installed bundle to be considered usable.
 */
class BundleSpec(
    val id: String,
    val liveDirs: List<String>,
    val mapPath: (String) -> String?,
    val postInstall: (stagingRoot: File) -> Unit,
    val sentinels: List<String>,
) {
    init {
        require(liveDirs.isNotEmpty())
    }

    val primaryDir: String get() = liveDirs.first()
}

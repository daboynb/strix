package org.csploit.strix.data.bundle

import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Locale

private val BUILT_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'", Locale.ROOT).withZone(ZoneOffset.UTC)

private fun withBuilt(m: BundleManifest): String? =
    m.built?.let { "${m.version} (built ${BUILT_FORMAT.format(Instant.ofEpochSecond(it))})" }

/**
 * Labels shown for the installed and the offered bundle. A rebuild of the same
 * upstream version ("msf 6.4.125" over "msf 6.4.125") would read as an update
 * to the same thing: then both carry their build time.
 */
internal fun versionLabels(
    installedLabel: String?,
    installed: BundleManifest?,
    offered: BundleManifest?,
): Pair<String?, String?> {
    if (offered == null || installed == null || installed.version != offered.version) {
        return installedLabel to offered?.version
    }
    return (withBuilt(installed) ?: installedLabel) to (withBuilt(offered) ?: offered.version)
}

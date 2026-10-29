package org.csploit.strix.data.bundle

/** What a bundle channel is doing right now. */
sealed interface BundleOp {
    data object Idle : BundleOp
    data object Checking : BundleOp
    data class Downloading(val bytes: Long, val total: Long) : BundleOp
    data object Verifying : BundleOp
    data class Installing(val bytes: Long, val total: Long) : BundleOp
    /** Staged and verified; [reason] says what must stop before the swap. */
    data class PendingSwap(val version: String, val reason: String) : BundleOp
    data class Error(val message: String) : BundleOp

    val busy: Boolean
        get() = this is Checking || this is Downloading || this is Verifying || this is Installing
}

data class BundleState(
    /** User-facing bundle name ("Metasploit", "Tools"). */
    val label: String,
    /** null = not installed, [BundleVersions.LEGACY] = extracted by an older APK. */
    val installedVersion: String? = null,
    /** Where the installed copy came from ("APK", "downloaded"), if meaningful. */
    val source: String? = null,
    /** Newer version offered by the last check, null if none / unknown. */
    val availableVersion: String? = null,
    /** Archive size of the offered version, if known. */
    val downloadSize: Long? = null,
    val lastCheckMs: Long = 0L,
    val op: BundleOp = BundleOp.Idle,
    /** One-shot informational result, e.g. "Tools are up to date". */
    val message: String? = null,
)

/** A verified (signature-checked) candidate from the latest release. */
internal data class VerifiedCandidate(
    val release: BundleRelease,
    val manifest: BundleManifest,
    val manifestJson: String,
    val archive: ReleaseAsset,
)

/** Platform bits a channel needs; an interface so the logic stays JVM-testable. */
interface BundleEnv {
    fun isOnWifi(): Boolean
    fun appVersionCode(): Long
    /** One GitHub API call: the releases list json (serves both bundles). */
    fun fetchReleasesJson(): String
}

/** Bundle-specific behaviour plugged into a [BundleChannel]. */
class BundleHooks(
    /** Installed manifest; null if not installed or a legacy install without manifest. */
    val installedManifest: () -> BundleManifest?,
    /** Installed version label: version, [BundleVersions.LEGACY], or null. */
    val installedLabel: () -> String?,
    val source: () -> String? = { null },
    /** Null if the live dirs may be swapped now, else what the user must stop first. Blocking ok (IO). */
    val swapBlocker: () -> String?,
    val beforeSwap: suspend () -> Unit = {},
    val afterSwap: suspend () -> Unit = {},
    /** Serializes stage/swap with other writers of the same bundle (APK tools install). */
    val lock: kotlinx.coroutines.sync.Mutex? = null,
)

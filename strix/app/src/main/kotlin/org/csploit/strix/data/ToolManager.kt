package org.csploit.strix.data

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.csploit.strix.core.Logger
import org.csploit.strix.data.bundle.BundleInstaller
import org.csploit.strix.data.bundle.BundleManifest
import org.csploit.strix.data.bundle.BundleSpec
import org.csploit.strix.data.bundle.BundleVersions
import org.csploit.strix.domain.model.ExtractionState
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Paths of the native bundles and the APK side of the tools bundle. Tools
 * ship in the APK as an offline baseline and can be updated at runtime;
 * MSF is download-only. Downloads are handled by
 * [org.csploit.strix.data.bundle.BundleUpdateManager].
 */
@Singleton
class ToolManager @Inject constructor(
    @ApplicationContext private val context: Context,
    toolsExtractor: ToolsExtractor,
    rubyExtractor: RubyExtractor,
    val installer: BundleInstaller,
) {
    private val _state = MutableStateFlow<ExtractionState>(ExtractionState.Idle)
    val state: StateFlow<ExtractionState> = _state

    val toolsSpec: BundleSpec = toolsExtractor.spec
    val msfSpec: BundleSpec = rubyExtractor.spec
    /** Serializes every stage/swap of the tools bundle (APK install vs downloaded update). */
    val toolsLock = Mutex()

    val toolsPath: String get() = context.filesDir.absolutePath + "/tools/"
    val rubyPath: String get() = context.filesDir.absolutePath + "/ruby/"
    val msfPath: String get() = context.filesDir.absolutePath + "/msf/"
    /** HOME of msfrpcd (holds ~/.msf4); outside ruby/ so bundle swaps keep user data. */
    val msfHomePath: String get() = context.filesDir.absolutePath + "/msf-home/"
    val corePath: String get() = context.filesDir.absolutePath

    fun isToolsInstalled(): Boolean = installer.sentinelsPresent(toolsSpec)

    fun isRubyInstalled(): Boolean = installer.sentinelsPresent(msfSpec)

    /** Installed version, [BundleVersions.LEGACY] for pre-manifest installs, null if not usable. */
    fun installedVersion(spec: BundleSpec): String? {
        if (!installer.sentinelsPresent(spec)) return null
        return installer.readInstalled(spec)?.version ?: BundleVersions.LEGACY
    }

    fun installedMsfVersion(): String? = installedVersion(msfSpec)

    fun installedToolsVersion(): String? = installedVersion(toolsSpec)

    fun isMsfInstalled(): Boolean = installedMsfVersion() != null

    /** Installed manifest if the bundle is usable; null when missing or legacy (no manifest). */
    fun installedManifest(spec: BundleSpec): BundleManifest? =
        if (installer.sentinelsPresent(spec)) installer.readInstalled(spec) else null

    private val apkToolsJson: String by lazy {
        context.assets.open(ToolsExtractor.ASSET_MANIFEST).bufferedReader().use { it.readText() }
    }

    /** Manifest of the tools bundle shipped in this APK. */
    fun apkToolsManifest(): BundleManifest = BundleManifest.parse(apkToolsJson)

    /** "APK" when the installed tools are this APK's copy, "downloaded" otherwise. */
    fun toolsSource(): String? {
        val installed = installedManifest(toolsSpec) ?: return installedToolsVersion()?.let { "APK" }
        val apk = runCatching { apkToolsManifest() }.getOrNull()
        return if (installed.sameContentAs(apk)) "APK" else "downloaded"
    }

    /**
     * Install the APK's tools bundle when missing, legacy, or older than the
     * APK copy (see [BundleVersions.shouldInstallApkCopy]: a downloaded bundle
     * newer than the APK is kept). [force] reinstalls the APK copy anyway.
     * Callers must make sure no tool is running.
     */
    suspend fun extractTools(force: Boolean = false) = withContext(Dispatchers.IO) {
        toolsLock.withLock {
            installer.cleanupLeftovers()
            _state.value = ExtractionState.Checking
            try {
                val json = apkToolsJson
                val manifest = BundleManifest.parse(json)
                val installed = installer.readInstalled(toolsSpec)
                if (!force && !BundleVersions.shouldInstallApkCopy(manifest, installed, isToolsInstalled())) {
                    _state.value = ExtractionState.AlreadyInstalled
                    return@withLock
                }
                Logger.info("ToolManager: installing tools ${manifest.version} (installed: ${installed?.version ?: installedToolsVersion()})")
                _state.value = ExtractionState.Extracting(0, "")
                context.assets.open(ToolsExtractor.ASSET_BUNDLE).use { input ->
                    installer.stage(toolsSpec, input, manifest, json) { _, files ->
                        if (files >= 0) _state.value = ExtractionState.Extracting(files, "")
                    }
                }
                _state.value = ExtractionState.PatchingConfig
                installer.swap(toolsSpec)
                _state.value = ExtractionState.Complete
                Logger.info("ToolManager: tools ${manifest.version} installed")
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Logger.error("ToolManager: tools install failed: ${e.message}")
                _state.value = ExtractionState.Error("Tools extraction failed: ${e.message}")
            }
        }
    }
}

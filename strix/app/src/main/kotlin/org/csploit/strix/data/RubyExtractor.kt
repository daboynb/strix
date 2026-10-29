package org.csploit.strix.data

import org.csploit.strix.core.Logger
import org.csploit.strix.data.bundle.BundleSpec
import org.csploit.strix.data.bundle.BundleVersions
import java.io.File
import java.nio.file.Files
import java.nio.file.Paths
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Layout + post-install patches of the Ruby + Metasploit bundle (downloaded
 * from GitHub releases, see [org.csploit.strix.data.bundle.BundleUpdateManager]).
 * The archive holds `ruby-android/` and `metasploit-framework/`, installed as
 * `filesDir/ruby/` and `filesDir/msf/`. Patches run on the freshly staged
 * tree, so every directory lookup sees exactly one candidate.
 */
@Singleton
class RubyExtractor @Inject constructor() {

    companion object {
        const val ID = "msf"
        private val RUBY_API_DIR = Regex("\\d+\\.\\d+\\.\\d+")

        /** Highest `x.y.z` dir under `ruby/lib/ruby`, or null. */
        fun detectRubyApiVersion(rubyDir: File): String? =
            File(rubyDir, "lib/ruby").listFiles()
                ?.filter { it.isDirectory && it.name.matches(RUBY_API_DIR) }
                ?.maxWithOrNull { a, b -> BundleVersions.compareVersions(a.name, b.name) }
                ?.name
    }

    val spec = BundleSpec(
        id = ID,
        liveDirs = listOf("msf", "ruby"),
        mapPath = ::mapPath,
        postInstall = { staging -> fixGemPaths(File(staging, "msf"), File(staging, "ruby")) },
        sentinels = listOf("ruby/bin/ruby", "msf/msfconsole"),
    )

    private fun mapPath(archivePath: String): String? = when {
        archivePath.startsWith("ruby-android/") -> "ruby/" + archivePath.removePrefix("ruby-android/")
        archivePath.startsWith("ruby/") -> archivePath
        archivePath.startsWith("metasploit-framework/") -> "msf/" + archivePath.removePrefix("metasploit-framework/")
        archivePath.startsWith("msf/") -> archivePath
        else -> null
    }

    /** Fix gem extension paths; all versions are discovered from the tree. Throws on failure. */
    private fun fixGemPaths(msfDir: File, rubyDir: File) {
        val rubyApiVersion = detectRubyApiVersion(rubyDir)
            ?: throw IllegalStateException("cannot detect ruby API version in $rubyDir/lib/ruby")
        Logger.info("RubyExtractor: detected ruby API version $rubyApiVersion")
        val rubyMajorMinor = rubyApiVersion.split(".").take(2).joinToString(".")

        val bundleRubyDir = File(msfDir, "vendor/bundle/ruby/$rubyApiVersion")
        fixExtensionSymlinks(File(bundleRubyDir, "extensions"))
        fixExtensionSymlinks(File(rubyDir, "lib/ruby/gems/$rubyApiVersion/extensions"))

        val gems = File(bundleRubyDir, "gems").listFiles()?.filter { it.isDirectory }.orEmpty()

        // Nokogiri loads lib/nokogiri/<major.minor>/nokogiri.so
        gems.newestWithPrefix("nokogiri-")?.let { nokogiriGem ->
            val nokogiriLib = File(nokogiriGem, "lib/nokogiri")
            if (nokogiriLib.exists()) {
                val versionDir = File(nokogiriLib, rubyMajorMinor)
                versionDir.mkdirs()
                createSymlink(File(versionDir, "nokogiri.so"), "../nokogiri.so")
                Logger.info("RubyExtractor: fixed nokogiri $rubyMajorMinor/ symlink")
            }
        }

        // Vendor json gem overrides the stdlib one
        gems.newestWithPrefix("json-")?.let { jsonGem ->
            val vendorJsonLib = File(jsonGem, "lib/json")
            val stdlibJsonDir = File(rubyDir, "lib/ruby/$rubyApiVersion/json")
            if (vendorJsonLib.exists() && stdlibJsonDir.exists()) {
                vendorJsonLib.listFiles()
                    ?.filter { it.isFile && it.name.endsWith(".rb") }
                    ?.forEach { src -> src.copyTo(File(stdlibJsonDir, src.name), overwrite = true) }
                Logger.info("RubyExtractor: patched stdlib json with vendor ${jsonGem.name}")
            }
        }

        File(msfDir, "msfrpcd").apply {
            writeText(MsfrpcdScript.CONTENT)
            setExecutable(true, false)
        }
        Logger.info("RubyExtractor: wrote msfrpcd compatibility script")
    }

    private fun List<File>.newestWithPrefix(prefix: String): File? =
        filter { it.name.startsWith(prefix) }
            .maxWithOrNull { a, b -> BundleVersions.compareVersions(a.name.removePrefix(prefix), b.name.removePrefix(prefix)) }

    /**
     * In an extension dir, link `aarch64-linux` → the android platform dir
     * (e.g. `aarch64-linux-android-android`) and `<ver>-static` → `<ver>`.
     */
    private fun fixExtensionSymlinks(extDir: File) {
        if (!extDir.exists()) return
        val androidPlatformDir = extDir.listFiles()
            ?.filter { it.isDirectory && !Files.isSymbolicLink(it.toPath()) && it.name.contains("android") }
            ?.maxByOrNull { it.name }
            ?: return

        val shortName = androidPlatformDir.name.substringBefore("-android-android")
        if (shortName != androidPlatformDir.name) {
            createSymlink(File(extDir, shortName), androidPlatformDir.name)
        }

        androidPlatformDir.listFiles()
            ?.filter { it.isDirectory && !Files.isSymbolicLink(it.toPath()) && !it.name.contains("-static") }
            ?.forEach { versionDir ->
                val staticDir = File(androidPlatformDir, "${versionDir.name}-static")
                if (!staticDir.exists()) createSymlink(staticDir, versionDir.name)
            }
    }

    private fun createSymlink(linkFile: File, target: String) {
        val p = linkFile.toPath()
        if (!Files.isSymbolicLink(p) && linkFile.isDirectory) {
            // The bundle already ships a real directory here: nothing to alias.
            Logger.info("RubyExtractor: ${linkFile.name} is a real directory, keeping it")
            return
        }
        if (Files.isSymbolicLink(p) || linkFile.isFile) Files.delete(p)
        Files.createSymbolicLink(p, Paths.get(target))
    }
}

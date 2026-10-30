package org.csploit.strix.data

import org.csploit.strix.core.Logger
import org.csploit.strix.data.bundle.BundleVersions
import java.io.File
import java.nio.file.Files
import java.nio.file.Paths

/**
 * Post-install patches of the staged Ruby + Metasploit tree (see [RubyExtractor]):
 * extension symlinks, nokogiri `<major.minor>/` link, vendor json over stdlib
 * (older non load-relative Ruby only),
 * `msfrpcd` wrapper.
 */
internal object MsfBundlePatches {

    /** Fix gem extension paths; all versions are discovered from the tree. Throws on failure. */
    fun fixGemPaths(msfDir: File, rubyDir: File) {
        val rubyApiVersion = RubyExtractor.detectRubyApiVersion(rubyDir)
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

        // Older bundles (absolute load paths, run with RUBYLIB): the stdlib json
        // dir comes first, so overlay it with the vendor gem's .rb files.
        // Load-relative Ruby needs no RUBYLIB, gems win and this would break
        // plain `require "json"` (vendor .rb over the stdlib's static parser).
        if (!RubyExtractor.isLoadRelative(rubyDir)) gems.newestWithPrefix("json-")?.let { jsonGem ->
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

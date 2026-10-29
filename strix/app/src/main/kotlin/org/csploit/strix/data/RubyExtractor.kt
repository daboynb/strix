package org.csploit.strix.data

import org.csploit.strix.data.bundle.BundleSpec
import org.csploit.strix.data.bundle.BundleVersions
import java.io.File
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
        postInstall = { staging -> MsfBundlePatches.fixGemPaths(File(staging, "msf"), File(staging, "ruby")) },
        sentinels = listOf("ruby/bin/ruby", "msf/msfconsole"),
    )

    private fun mapPath(archivePath: String): String? = when {
        archivePath.startsWith("ruby-android/") -> "ruby/" + archivePath.removePrefix("ruby-android/")
        archivePath.startsWith("ruby/") -> archivePath
        archivePath.startsWith("metasploit-framework/") -> "msf/" + archivePath.removePrefix("metasploit-framework/")
        archivePath.startsWith("msf/") -> archivePath
        else -> null
    }
}

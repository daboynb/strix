package org.csploit.strix.data

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import org.csploit.strix.core.Logger
import org.csploit.strix.domain.model.ExtractionState
import java.io.BufferedInputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.Paths
import java.util.zip.GZIPInputStream
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class RubyExtractor @Inject constructor() {

    companion object {
        private const val ASSET_BUNDLE = "ruby-msf-bundle.tar.gz.bin"
    }

    fun extract(context: Context, state: MutableStateFlow<ExtractionState>) {
        val destDir = context.filesDir.absolutePath

        context.assets.open(ASSET_BUNDLE).use { inputStream ->
            extractTarGzWithMapping(inputStream, destDir, state)
        }

        state.value = ExtractionState.PatchingConfig
        val msfPath = "$destDir/msf"
        val rubyPath = "$destDir/ruby"
        fixGemPaths(msfPath, rubyPath)
    }

    private fun extractTarGzWithMapping(
        inputStream: java.io.InputStream,
        destDir: String,
        state: MutableStateFlow<ExtractionState>,
    ) {
        var filesExtracted = 0
        val buffer = ByteArray(65536)

        TarArchiveInputStream(
            GZIPInputStream(BufferedInputStream(inputStream, 65536))
        ).use { tar ->
            var entry = tar.nextTarEntry
            while (entry != null) {
                val name = mapPath(entry.name)
                if (name == null) {
                    entry = tar.nextTarEntry
                    continue
                }

                val outFile = File(destDir, name)

                if (entry.isDirectory) {
                    outFile.mkdirs()
                    entry = tar.nextTarEntry
                    continue
                }

                if (entry.isSymbolicLink || entry.isLink) {
                    deletePathSafe(outFile)
                    outFile.parentFile?.mkdirs()
                    try {
                        Files.createSymbolicLink(outFile.toPath(), Paths.get(entry.linkName))
                    } catch (e: Exception) {
                        Logger.warning("RubyExtractor: symlink failed: $name -> ${entry.linkName}")
                    }
                    filesExtracted++
                    entry = tar.nextTarEntry
                    continue
                }

                outFile.parentFile?.mkdirs()
                if (outFile.exists()) deletePathSafe(outFile)

                FileOutputStream(outFile).use { out ->
                    var len = tar.read(buffer)
                    while (len > 0) {
                        out.write(buffer, 0, len)
                        len = tar.read(buffer)
                    }
                }

                if (entry.mode and 0b001_001_001 != 0) {
                    outFile.setExecutable(true, false)
                }

                filesExtracted++
                if (filesExtracted % 100 == 0) {
                    state.value = ExtractionState.Extracting(filesExtracted, name)
                }
                entry = tar.nextTarEntry
            }
        }

        Logger.info("RubyExtractor: extracted $filesExtracted files to $destDir")
    }

    private fun mapPath(archivePath: String): String? = when {
        archivePath.startsWith("ruby-android/") -> "ruby/" + archivePath.removePrefix("ruby-android/")
        archivePath.startsWith("ruby/") -> archivePath
        archivePath.startsWith("metasploit-framework/") -> "msf/" + archivePath.removePrefix("metasploit-framework/")
        archivePath.startsWith("msf/") -> archivePath
        else -> null
    }

    /**
     * Fix gem extension paths after extraction.
     * All paths are discovered from the filesystem — no hardcoded versions.
     */
    private fun fixGemPaths(msfPath: String, rubyPath: String) {
        try {
            // Discover ruby API version from lib/ruby/<version>/ directory
            val rubyLibDir = File(rubyPath, "lib/ruby")
            val rubyApiVersion = rubyLibDir.listFiles()
                ?.firstOrNull { it.isDirectory && it.name.matches(Regex("\\d+\\.\\d+\\.\\d+")) }
                ?.name
            if (rubyApiVersion == null) {
                Logger.warning("RubyExtractor: cannot detect ruby API version in $rubyLibDir")
                return
            }
            Logger.info("RubyExtractor: detected ruby API version $rubyApiVersion")

            // Major.minor for gem subdirectory lookups (e.g. "3.3")
            val rubyMajorMinor = rubyApiVersion.split(".").take(2).joinToString(".")

            // Fix extensions: symlink aarch64-linux → aarch64-linux-android-android
            // and <version>-static → <version> in all extension dirs
            val bundleRubyDir = File(msfPath, "vendor/bundle/ruby/$rubyApiVersion")
            fixExtensionSymlinks(File(bundleRubyDir, "extensions"))
            fixExtensionSymlinks(File(rubyPath, "lib/ruby/gems/$rubyApiVersion/extensions"))

            // Fix Nokogiri: find the nokogiri gem dir and create version subdir symlink
            val gemsDir = File(bundleRubyDir, "gems")
            gemsDir.listFiles()
                ?.firstOrNull { it.isDirectory && it.name.startsWith("nokogiri-") }
                ?.let { nokogiriGem ->
                    val nokogiriLib = File(nokogiriGem, "lib/nokogiri")
                    val versionDir = File(nokogiriLib, rubyMajorMinor)
                    if (nokogiriLib.exists() && !versionDir.exists()) {
                        versionDir.mkdirs()
                        createSymlinkSafe(File(versionDir, "nokogiri.so"), "../nokogiri.so")
                        Logger.info("RubyExtractor: fixed nokogiri $rubyMajorMinor/ symlink")
                    }
                }

            // Fix JSON: copy vendor json lib over stdlib if vendor version exists
            gemsDir.listFiles()
                ?.firstOrNull { it.isDirectory && it.name.startsWith("json-") }
                ?.let { jsonGem ->
                    val vendorJsonLib = File(jsonGem, "lib/json")
                    val stdlibJsonDir = File(rubyPath, "lib/ruby/$rubyApiVersion/json")
                    if (vendorJsonLib.exists() && stdlibJsonDir.exists()) {
                        vendorJsonLib.listFiles()
                            ?.filter { it.isFile && it.name.endsWith(".rb") }
                            ?.forEach { src ->
                                val dst = File(stdlibJsonDir, src.name)
                                src.copyTo(dst, overwrite = true)
                            }
                        Logger.info("RubyExtractor: patched stdlib json with vendor ${jsonGem.name}")
                    }
                }

            createMsfrpcdScript(msfPath)
        } catch (e: Exception) {
            Logger.error("RubyExtractor: fixGemPaths failed: ${e.message}")
        }
    }

    private fun createMsfrpcdScript(msfPath: String) {
        val script = File(msfPath, "msfrpcd")
        if (script.exists()) return

        script.writeText(
            """
            |#!/usr/bin/env ruby
            |# msfrpcd - MSF RPC Daemon (compatibility wrapper for MSF 6.x)
            |
            |msfbase = __FILE__
            |while File.symlink?(msfbase)
            |  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
            |end
            |
            |${'$'}:.unshift(File.expand_path(File.join(File.dirname(msfbase), 'lib')))
            |require 'msfenv'
            |
            |opts = {
            |  'ServerHost' => '0.0.0.0',
            |  'ServerPort' => 55553,
            |  'User' => 'msf',
            |  'Pass' => 'msf',
            |  'SSL' => true,
            |}
            |
            |i = 0
            |while i < ARGV.length
            |  case ARGV[i]
            |  when '-a' then i += 1; opts['ServerHost'] = ARGV[i]
            |  when '-p' then i += 1; opts['ServerPort'] = ARGV[i].to_i
            |  when '-U' then i += 1; opts['User'] = ARGV[i]
            |  when '-P' then i += 1; opts['Pass'] = ARGV[i]
            |  when '-S' then opts['SSL'] = false
            |  end
            |  i += 1
            |end
            |
            |${'$'}0 = 'msfrpcd'
            |${'$'}stderr.puts "[*] MSGRPC starting on #{opts['ServerPort']} (#{opts['SSL'] ? 'SSL' : 'NO SSL'})..."
            |${'$'}stderr.flush
            |
            |framework = Msf::Simple::Framework.create
            |framework.plugins.load('msgrpc', opts)
            |
            |${'$'}stderr.puts "[*] MSGRPC ready at #{opts['ServerHost']}:#{opts['ServerPort']}"
            |${'$'}stderr.flush
            |
            |begin
            |  while true
            |    sleep 60
            |  end
            |rescue Interrupt, SignalException
            |  ${'$'}stderr.puts "[*] Shutting down msfrpcd..."
            |end
            """.trimMargin()
        )
        script.setExecutable(true, false)
        Logger.info("RubyExtractor: created msfrpcd compatibility script")
    }

    /**
     * Fix extension directory symlinks.
     * Discovers platform dirs (e.g. aarch64-linux-android-android) and creates:
     * - aarch64-linux → <actual platform dir> (short name symlink)
     * - <version>-static → <version> (bundler compatibility)
     */
    private fun fixExtensionSymlinks(extDir: File) {
        if (!extDir.exists()) return

        // Find the android platform directory
        val androidPlatformDir = extDir.listFiles()
            ?.firstOrNull { it.isDirectory && it.name.contains("android") }
            ?: return

        // Create short symlink: aarch64-linux → aarch64-linux-android-android
        val shortName = androidPlatformDir.name.substringBefore("-android-android")
        if (shortName != androidPlatformDir.name) {
            createSymlinkSafe(File(extDir, shortName), androidPlatformDir.name)
        }

        // Inside the platform dir, create <ver>-static → <ver> symlinks
        androidPlatformDir.listFiles()
            ?.filter { it.isDirectory && !it.name.contains("-static") }
            ?.forEach { versionDir ->
                val staticName = "${versionDir.name}-static"
                val staticDir = File(androidPlatformDir, staticName)
                if (!staticDir.exists()) {
                    createSymlinkSafe(staticDir, versionDir.name)
                }
            }
    }

    private fun createSymlinkSafe(linkFile: File, target: String) {
        deletePathSafe(linkFile)
        try {
            Files.createSymbolicLink(linkFile.toPath(), Paths.get(target))
        } catch (e: Exception) {
            Logger.warning("RubyExtractor: symlink failed: ${linkFile.name} -> $target: ${e.message}")
        }
    }

    private fun deletePathSafe(fileOrDir: File) {
        if (!fileOrDir.exists() && !Files.isSymbolicLink(fileOrDir.toPath())) return
        if (Files.isSymbolicLink(fileOrDir.toPath())) {
            fileOrDir.delete()
            return
        }
        if (fileOrDir.isDirectory) {
            fileOrDir.listFiles()?.forEach { deletePathSafe(it) }
        }
        fileOrDir.delete()
    }
}

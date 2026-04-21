package org.csploit.strix.data

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import org.csploit.strix.core.Logger
import org.csploit.strix.domain.model.ExtractionState
import java.io.BufferedInputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.zip.GZIPInputStream
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ToolsExtractor @Inject constructor() {

    companion object {
        private const val ASSET_BUNDLE = "tools-bundle.tar.gz.bin"
    }

    fun extract(context: Context, state: MutableStateFlow<ExtractionState>) {
        val destDir = context.filesDir.absolutePath + "/tools"
        val toolsDir = File(destDir)
        toolsDir.mkdirs()
        toolsDir.setReadable(true, false)
        toolsDir.setExecutable(true, false)

        context.assets.open(ASSET_BUNDLE).use { inputStream ->
            extractTarGz(inputStream, destDir, state)
        }

        state.value = ExtractionState.PatchingConfig
        patchEtterConf(File(destDir, "etc/ettercap/etter.conf"))
    }

    private fun extractTarGz(
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
                if (entry.isDirectory) {
                    val dir = File(destDir, entry.name)
                    dir.mkdirs()
                    dir.setReadable(true, false)
                    dir.setExecutable(true, false)
                    entry = tar.nextTarEntry
                    continue
                }

                val outFile = File(destDir, entry.name)
                outFile.parentFile?.mkdirs()

                if (entry.isSymbolicLink) {
                    val targetFile = File(outFile.parentFile, entry.linkName)
                    if (targetFile.exists()) {
                        FileInputStream(targetFile).use { src ->
                            FileOutputStream(outFile).use { dst ->
                                var len = src.read(buffer)
                                while (len > 0) {
                                    dst.write(buffer, 0, len)
                                    len = src.read(buffer)
                                }
                            }
                        }
                        outFile.setExecutable(targetFile.canExecute(), false)
                    }
                    filesExtracted++
                    entry = tar.nextTarEntry
                    continue
                }

                FileOutputStream(outFile).use { out ->
                    var len = tar.read(buffer)
                    while (len > 0) {
                        out.write(buffer, 0, len)
                        len = tar.read(buffer)
                    }
                }

                outFile.setReadable(true, false)
                if (entry.mode and 0b001_001_001 != 0) {
                    outFile.setExecutable(true, false)
                }

                filesExtracted++
                if (filesExtracted % 100 == 0) {
                    state.value = ExtractionState.Extracting(filesExtracted, entry.name)
                }
                entry = tar.nextTarEntry
            }
        }

        Logger.info("ToolsExtractor: extracted $filesExtracted files to $destDir")
    }

    private fun patchEtterConf(etterConf: File) {
        if (!etterConf.exists()) return
        try {
            var content = etterConf.readText()
            content = content.replace("ec_uid = 65534", "ec_uid = 0")
            content = content.replace("ec_gid = 65534", "ec_gid = 0")
            content = content.replace(
                "utf8_encoding = \"ISO-8859-1\"",
                "#utf8_encoding = \"ISO-8859-1\"",
            )
            etterConf.writeText(content)
            etterConf.setReadable(true, false)
            Logger.info("ToolsExtractor: patched etter.conf (ec_uid/gid=0)")
        } catch (e: Exception) {
            Logger.warning("ToolsExtractor: could not patch etter.conf: ${e.message}")
        }
    }
}

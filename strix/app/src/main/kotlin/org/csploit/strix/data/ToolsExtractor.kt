package org.csploit.strix.data

import org.csploit.strix.core.Logger
import org.csploit.strix.data.bundle.BundleSpec
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Layout + post-install patches of the tools bundle (shipped in the APK as
 * `assets/tools-bundle.tar.gz.bin`, described by `assets/tools-bundle.json`).
 * Extraction itself is done by [org.csploit.strix.data.bundle.BundleInstaller].
 */
@Singleton
class ToolsExtractor @Inject constructor() {

    companion object {
        const val ID = "tools"
        const val ASSET_BUNDLE = "tools-bundle.tar.gz.bin"
        const val ASSET_MANIFEST = "tools-bundle.json"
    }

    val spec = BundleSpec(
        id = ID,
        liveDirs = listOf("tools"),
        // The archive root is the tools dir itself (bin/, lib/, share/, etc/).
        mapPath = { name -> "tools/$name" },
        postInstall = { staging ->
            val tools = File(staging, "tools")
            tools.setReadable(true, false)
            tools.setExecutable(true, false)
            patchEtterConf(File(tools, "etc/ettercap/etter.conf"))
        },
        sentinels = listOf(
            "tools/bin/nmap",
            "tools/bin/hydra",
            "tools/bin/ettercap",
            "tools/bin/arpspoof",
            "tools/bin/tcpdump",
            "tools/lib/libettercap.so.0",
        ),
    )

    /** ettercap must run as root (it drops to 65534 by default) and the ISO charset breaks on Android. */
    internal fun patchEtterConf(etterConf: File) {
        if (!etterConf.exists()) return
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
    }
}

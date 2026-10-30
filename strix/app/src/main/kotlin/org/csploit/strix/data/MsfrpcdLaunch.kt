package org.csploit.strix.data

import org.csploit.strix.core.shellQuote
import java.io.File

/** Command line, environment and secrets to redact for one msfrpcd run. */
internal class MsfrpcdLaunch(
    val command: String,
    val env: Map<String, String>,
    val secrets: List<String>,
    val port: Int,
)

/** Build the msfrpcd invocation from the installed bundle paths and RPC settings. */
internal fun buildMsfrpcdLaunch(toolManager: ToolManager, appSettings: AppSettings): MsfrpcdLaunch {
    val homePath = toolManager.msfHomePath.trimEnd('/')
    val rubyPath = toolManager.rubyPath.trimEnd('/')
    val msfPath = toolManager.msfPath.trimEnd('/')
    val rubyBin = "$rubyPath/bin/ruby"
    val rubyApiVersion = RubyExtractor.detectRubyApiVersion(File(rubyPath)) ?: "3.3.0"

    val user = appSettings.msfRpcUser
    val pass = appSettings.msfRpcPassword
    val port = appSettings.msfRpcPort
    val disableSslFlag = if (appSettings.msfRpcSsl) "" else " -S"

    // -f keeps msfrpcd in foreground so ProcessManager can track it
    val cmd = "$rubyBin $msfPath/msfrpcd -f -a 127.0.0.1 -p $port " +
        "-U ${shellQuote(user)} -P ${shellQuote(pass)}$disableSslFlag"
    // Quoted form first: with a ' in the password the raw string is not a
    // substring of the command line.
    val secrets = if (pass.isEmpty()) emptyList() else listOf(shellQuote(pass), pass)

    // Load-relative Ruby finds its stdlib itself; RUBYLIB would shadow the
    // bundled gems (e.g. the json gem) with the stdlib copies.
    val rubyLib = if (RubyExtractor.isLoadRelative(File(rubyPath))) {
        emptyMap()
    } else {
        mapOf("RUBYLIB" to "$rubyPath/lib/ruby/$rubyApiVersion:${detectArchDir(rubyPath, rubyApiVersion)}")
    }
    val env = rubyLib + mapOf(
        "HOME" to homePath,
        "PATH" to "$rubyPath/bin:$msfPath:/system/bin:/system/xbin",
        "LD_LIBRARY_PATH" to "$rubyPath/lib",
        "GEM_HOME" to "$msfPath/vendor/bundle/ruby/$rubyApiVersion",
        "GEM_PATH" to "$msfPath/vendor/bundle/ruby/$rubyApiVersion:$rubyPath/lib/ruby/gems/$rubyApiVersion",
        "OPENSSL_CONF" to "$rubyPath/ssl/openssl.cnf",
        "OPENSSL_MODULES" to "$rubyPath/lib/ossl-modules",
    )
    return MsfrpcdLaunch(cmd, env, secrets, port)
}

/** Find the arch-specific directory (e.g. aarch64-linux-android-android) */
private fun detectArchDir(rubyPath: String, apiVersion: String): String {
    val versionDir = File(rubyPath, "lib/ruby/$apiVersion")
    val archDir = versionDir.listFiles()
        ?.filter { it.isDirectory && it.name.startsWith("aarch64") }
        ?.maxByOrNull { it.name }
        ?.absolutePath
    return archDir ?: "$rubyPath/lib/ruby/$apiVersion/aarch64-linux"
}

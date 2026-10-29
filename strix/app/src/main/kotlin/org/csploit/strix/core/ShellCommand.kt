package org.csploit.strix.core

// First stdout line of every wrapper shell: its own PID, consumed by
// ProcessManager (never emitted) so cancellation can kill the whole process tree.
internal const val PID_MARKER = "__STRIX_PID__"

/**
 * Quote [s] as a single POSIX shell word: wrap in single quotes and turn every
 * embedded `'` into `'\''`. Use for every user-controlled value that ends up in
 * a command passed to [ProcessManager.execute].
 */
fun shellQuote(s: String): String = "'" + s.replace("'", "'\\''") + "'"

/** Replace every non-blank secret in [text] with "***" (longest first, so overlapping secrets don't leak). */
internal fun redactSecrets(text: String, secrets: Collection<String>): String =
    secrets.filter { it.isNotBlank() }
        .sortedByDescending { it.length }
        .fold(text) { acc, secret -> acc.replace(secret, "***") }

internal fun buildShellCommand(
    command: String,
    env: Map<String, String>,
    toolsDir: String?,
    workDir: String?,
): String = buildString {
    val dollar = '$'
    append("echo ").append(PID_MARKER).append(dollar).append(dollar).append(" ; ")
    if (workDir != null) {
        append("cd ").append(shellQuote(workDir)).append(" ; ")
    }
    if (toolsDir != null) {
        val dir = toolsDir.trimEnd('/')
        append("export PATH=").append(shellQuote("$dir/bin")).append(":").append(dollar).append("PATH ; ")
        append("export NMAPDIR=").append(shellQuote("$dir/share/nmap")).append(" ; ")
    }
    for ((key, value) in env) {
        append("export ").append(key).append("=").append(shellQuote(value)).append(" ; ")
    }
    append(command)
}

package org.csploit.strix.ui.bruteforce

import org.csploit.strix.core.shellQuote

/**
 * Build the hydra command line for [local]'s method and password source.
 * [defaultUsers]/[defaultPasswords] are used when no custom wordlist is picked.
 */
internal fun buildHydraCommand(
    local: LocalState,
    ip: String,
    port: Int,
    threads: Int,
    defaultUsers: String,
    defaultPasswords: String,
): String {
    val method = local.method
    val usersPath = local.customUsersPath ?: defaultUsers

    val passArg = when (local.passwordMode) {
        PasswordMode.WORDLIST -> {
            val path = local.customPasswordsPath ?: defaultPasswords
            "-P ${shellQuote(path)}"
        }
        PasswordMode.CHARSET -> {
            val charset = buildString {
                if (local.charsetLower) append("a")
                if (local.charsetUpper) append("A")
                if (local.charsetDigits) append("1")
            }
            "-x ${local.passMin}:${local.passMax}:$charset"
        }
    }

    val needsPath = method.contains("http")
    // The http(s)-post-form spec ("/login.php:user=^USER^&pass=^PASS^:F=x")
    // contains shell metacharacters: every user-controlled word is quoted.
    val target = if (needsPath) {
        "${shellQuote(ip)} ${shellQuote(method)} ${shellQuote(local.path)}"
    } else {
        "${shellQuote(ip)} ${shellQuote(method)}"
    }

    // -I: a Stop leaves ./hydra.restore behind; without it the next run waits 10 s on it.
    return "hydra -I -L ${shellQuote(usersPath)} $passArg -f -t $threads -s $port $target"
}

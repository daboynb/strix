package org.csploit.strix.ui.mitm

import android.util.Base64
import org.csploit.strix.data.MitmRunner

/**
 * Parse tcpdump ASCII output for credentials.
 * HTTP Basic Auth, POST form data, FTP USER/PASS.
 */
internal class MitmTrafficParser(
    private val ip: String,
    private val log: (String) -> Unit,
    private val onCredential: (protocol: String, endpoint: String, user: String, pass: String) -> Unit,
) {
    private var lastFtpUser: String? = null

    fun parse(line: String) {
        // HTTP Basic Auth: "Authorization: Basic BASE64"
        MitmRunner.BASIC_AUTH_REGEX.find(line)?.let { match ->
            val decoded = try {
                String(Base64.decode(match.groupValues[1], Base64.DEFAULT))
            } catch (_: Exception) { return@let }
            val parts = decoded.split(":", limit = 2)
            if (parts.size == 2) {
                onCredential("HTTP", "Basic Auth", parts[0], parts[1])
                log("[!] HTTP Basic Auth: ${parts[0]}:${parts[1]}")
            }
            return
        }

        // POST form: "username=X&password=Y"
        MitmRunner.POST_CRED_REGEX.find(line)?.let { match ->
            onCredential("HTTP", "POST", match.groupValues[1], match.groupValues[2])
            log("[!] HTTP POST: ${match.groupValues[1]}:${match.groupValues[2]}")
            return
        }

        // FTP: "USER xxx" / "PASS xxx"
        MitmRunner.FTP_REGEX.find(line)?.let { match ->
            val cmd = match.groupValues[1].uppercase()
            val value = match.groupValues[2].trim()
            if (cmd == "USER") {
                lastFtpUser = value
            } else if (cmd == "PASS" && lastFtpUser != null) {
                onCredential("FTP", ip, lastFtpUser!!, value)
                log("[!] FTP: $lastFtpUser:$value")
                lastFtpUser = null
            }
            return
        }
    }
}

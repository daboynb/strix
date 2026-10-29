package org.csploit.strix.ui.bruteforce

import org.csploit.strix.data.BruteForceSession

enum class PasswordMode { WORDLIST, CHARSET }

data class BruteForceUiState(
    val isRunning: Boolean = false,
    val methods: List<String> = emptyList(),
    val method: String = "",
    val path: String = "/",
    val logLines: List<String> = emptyList(),
    val foundCreds: String? = null,
    val customUsersPath: String? = null,
    val customPasswordsPath: String? = null,
    val passwordMode: PasswordMode = PasswordMode.WORDLIST,
    val charsetLower: Boolean = true,
    val charsetUpper: Boolean = false,
    val charsetDigits: Boolean = true,
    val passMin: Int = 1,
    val passMax: Int = 6,
    val statusLine: String? = null,
    val progress: Float? = null,
)
/** UI-selected fields; persistent attack state lives in [BruteForceSessionStore]. */
internal data class LocalState(
    val method: String,
    val path: String = "/",
    val customUsersPath: String? = null,
    val customPasswordsPath: String? = null,
    val passwordMode: PasswordMode = PasswordMode.WORDLIST,
    val charsetLower: Boolean = true,
    val charsetUpper: Boolean = false,
    val charsetDigits: Boolean = true,
    val passMin: Int = 1,
    val passMax: Int = 6,
)

internal fun BruteForceSession?.toUiState(
    local: LocalState,
    methods: List<String>,
): BruteForceUiState = BruteForceUiState(
    isRunning = this?.isRunning ?: false,
    methods = methods,
    method = local.method,
    path = local.path,
    logLines = this?.logLines ?: emptyList(),
    foundCreds = this?.foundCreds,
    customUsersPath = local.customUsersPath,
    customPasswordsPath = local.customPasswordsPath,
    passwordMode = local.passwordMode,
    charsetLower = local.charsetLower,
    charsetUpper = local.charsetUpper,
    charsetDigits = local.charsetDigits,
    passMin = local.passMin,
    passMax = local.passMax,
    statusLine = this?.statusLine,
    progress = this?.progress,
)

package org.csploit.strix.ui.bruteforce

import android.content.Context
import android.net.Uri
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.csploit.strix.core.Logger
import org.csploit.strix.core.ProcessEvent
import org.csploit.strix.core.ProcessManager
import org.csploit.strix.core.ScanRegistry
import org.csploit.strix.data.AppSettings
import org.csploit.strix.data.BruteForceSession
import org.csploit.strix.data.BruteForceSessionStore
import org.csploit.strix.data.CredentialTester
import org.csploit.strix.data.HydraModules
import org.csploit.strix.data.ToolManager
import org.csploit.strix.ui.navigation.Routes
import java.io.File
import javax.inject.Inject

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
private data class LocalState(
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

@HiltViewModel
class BruteForceViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
    savedStateHandle: SavedStateHandle,
    private val processManager: ProcessManager,
    private val credentialTester: CredentialTester,
    private val toolManager: ToolManager,
    private val appSettings: AppSettings,
    private val scanRegistry: ScanRegistry,
    private val store: BruteForceSessionStore,
) : ViewModel() {

    val ip: String = savedStateHandle["ip"] ?: ""
    val port: Int = savedStateHandle.get<String>("port")?.toIntOrNull() ?: 80
    val service: String? = savedStateHandle.get<String>("service")?.takeIf { it != "unknown" }

    private val attacks = HydraModules.forService(service, port)
    private val methods: List<String> = attacks.map { it.module }

    private val _local = MutableStateFlow(
        LocalState(method = attacks.firstOrNull()?.module ?: "http-get"),
    )

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    val uiState: StateFlow<BruteForceUiState> = combine(
        _local,
        _local.flatMapLatest { local ->
            store.sessions.map { it[BruteForceSessionStore.keyFor(ip, port, local.method)] }
        },
    ) { local, session ->
        session.toUiState(local)
    }.stateIn(viewModelScope, SharingStarted.Eagerly, null.toUiState(_local.value))

    private var hydraJob: Job? = null

    fun setMethod(method: String) {
        _local.value = _local.value.copy(method = method)
    }

    fun setPath(path: String) {
        _local.value = _local.value.copy(path = path)
    }

    fun setPasswordMode(mode: PasswordMode) {
        _local.value = _local.value.copy(passwordMode = mode)
    }

    fun setCharset(lower: Boolean, upper: Boolean, digits: Boolean) {
        _local.value = _local.value.copy(
            charsetLower = lower,
            charsetUpper = upper,
            charsetDigits = digits,
        )
    }

    fun setPassRange(min: Int, max: Int) {
        val cleanMin = min.coerceIn(1, 8)
        val cleanMax = max.coerceAtLeast(cleanMin).coerceIn(1, 8)
        _local.value = _local.value.copy(passMin = cleanMin, passMax = cleanMax)
    }

    fun pickUsersFile(uri: Uri) {
        viewModelScope.launch(Dispatchers.IO) {
            copyUriToInternal(uri, "users_custom.txt")?.let { path ->
                _local.value = _local.value.copy(customUsersPath = path)
                val key = currentKey()
                store.appendLog(key, "[+] Users wordlist: $path")
            }
        }
    }

    fun pickPasswordsFile(uri: Uri) {
        viewModelScope.launch(Dispatchers.IO) {
            copyUriToInternal(uri, "passwords_custom.txt")?.let { path ->
                _local.value = _local.value.copy(customPasswordsPath = path)
                val key = currentKey()
                store.appendLog(key, "[+] Passwords wordlist: $path")
            }
        }
    }

    fun clearCustomUsers() {
        _local.value = _local.value.copy(customUsersPath = null)
    }

    fun clearCustomPasswords() {
        _local.value = _local.value.copy(customPasswordsPath = null)
    }

    private suspend fun copyUriToInternal(uri: Uri, name: String): String? =
        withContext(Dispatchers.IO) {
            try {
                val outFile = File(toolManager.corePath, name)
                context.contentResolver.openInputStream(uri)?.use { input ->
                    outFile.outputStream().use { input.copyTo(it) }
                }
                outFile.setReadable(true, false)
                outFile.absolutePath
            } catch (e: Exception) {
                Logger.warning("copyUriToInternal failed: ${e.message}")
                null
            }
        }

    fun start() {
        hydraJob?.cancel()
        val local = _local.value
        val method = local.method
        val key = BruteForceSessionStore.keyFor(ip, port, method)

        if (local.passwordMode == PasswordMode.CHARSET) {
            if (!local.charsetLower && !local.charsetUpper && !local.charsetDigits) {
                store.appendLog(key, "[!] Select at least one charset class (a-z, A-Z, 0-9)")
                return
            }
        }

        store.resetForNewRun(key, ip, port, method)

        val (defaultUsers, defaultPasswords) = credentialTester.getWordlistPaths()
        val usersPath = local.customUsersPath ?: defaultUsers

        val passArg = when (local.passwordMode) {
            PasswordMode.WORDLIST -> {
                val path = local.customPasswordsPath ?: defaultPasswords
                "-P '$path'"
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
        val target = if (needsPath) "$ip $method ${local.path}" else "$ip $method"

        val credRegex = Regex("""\[\d+]\[\S+]\s+host:\s+\S+\s+login:\s+(\S+)\s+password:\s*(.*)""")
        val statusRegex = Regex(
            """\[STATUS]\s*\S+\s+tries/min,\s*(\d+)\s+tries.*?(\d+)\s+todo""",
            RegexOption.IGNORE_CASE,
        )

        val command = "hydra -L '$usersPath' $passArg -f -t ${appSettings.hydraThreads} -s $port $target"
        store.appendLog(key, "[+] $command")

        hydraJob = scanRegistry.launch(
            id = "bruteforce:$ip:$port:$method",
            label = "Hydra $method $ip:$port",
            deepLink = Routes.deepLinkBruteForce(ip, port, service),
        ) {
            processManager.execute(
                command = command,
                toolsDir = toolManager.toolsPath,
                workDir = toolManager.corePath,
            ).collect { event ->
                when (event) {
                    is ProcessEvent.StdoutLine -> {
                        store.appendLog(key, event.line)
                        credRegex.find(event.line)?.let { match ->
                            val creds = "${match.groupValues[1]}:${match.groupValues[2].trim()}"
                            store.setFoundCreds(key, creds)
                            scanRegistry.notifications.notifyCredentialCaptured(
                                host = "$ip:$port ($method)",
                                credential = creds,
                                deepLink = Routes.deepLinkBruteForce(ip, port, service),
                            )
                        }
                        statusRegex.find(event.line)?.let { match ->
                            val tries = match.groupValues[1].toLongOrNull() ?: 0
                            val todo = match.groupValues[2].toLongOrNull() ?: 0
                            val total = tries + todo
                            val pct = if (total > 0) tries.toFloat() / total else null
                            store.setStatus(key, event.line.trim(), pct)
                        }
                    }
                    is ProcessEvent.StderrLine -> store.appendLog(key, event.line)
                    is ProcessEvent.Exited -> {
                        store.appendLog(key, "[exited: ${event.code}]")
                        store.setRunning(key, false)
                        val found = store.sessionOf(key)?.foundCreds
                        scanRegistry.notifications.notifyScanComplete(
                            title = "Brute-force complete",
                            message = if (found != null) "$ip:$port — found $found" else "$ip:$port — no creds found",
                            deepLink = Routes.deepLinkBruteForce(ip, port, service),
                        )
                    }
                    is ProcessEvent.Killed -> {
                        store.appendLog(key, "[killed: signal ${event.signal}]")
                        store.setRunning(key, false)
                    }
                }
            }
        }
    }

    fun stop() {
        val method = _local.value.method
        scanRegistry.cancel("bruteforce:$ip:$port:$method")
        hydraJob = null
        store.appendLog(BruteForceSessionStore.keyFor(ip, port, method), "[stopped by user]")
        store.setRunning(BruteForceSessionStore.keyFor(ip, port, method), false)
    }

    private fun currentKey() = BruteForceSessionStore.keyFor(ip, port, _local.value.method)

    override fun onCleared() {
        super.onCleared()
        // hydraJob lives in ScanRegistry.appScope and intentionally survives VM destruction.
    }

    private fun BruteForceSession?.toUiState(local: LocalState): BruteForceUiState = BruteForceUiState(
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
}

package org.csploit.strix.ui.splash

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.csploit.strix.core.Logger
import org.csploit.strix.core.RootChecker
import org.csploit.strix.data.NetworkManager
import org.csploit.strix.data.ToolManager
import org.csploit.strix.domain.model.ExtractionState
import org.csploit.strix.domain.model.NetworkInfo
import javax.inject.Inject

data class SplashUiState(
    val step: StartupStep = StartupStep.WAITING_PERMISSIONS,
    val hasRoot: Boolean? = null,
    val extractionState: ExtractionState = ExtractionState.Idle,
    val networkInfo: NetworkInfo? = null,
    val error: String? = null,
)

enum class StartupStep {
    WAITING_PERMISSIONS,
    CHECKING_ROOT,
    EXTRACTING_TOOLS,
    DETECTING_NETWORK,
    READY,
    FAILED,
}

@HiltViewModel
class SplashViewModel @Inject constructor(
    private val rootChecker: RootChecker,
    private val toolManager: ToolManager,
    private val networkManager: NetworkManager,
) : ViewModel() {

    private val _uiState = MutableStateFlow(SplashUiState())
    val uiState: StateFlow<SplashUiState> = _uiState.asStateFlow()

    /**
     * Called after runtime permissions are granted.
     * Orchestrates the startup sequence: root -> tools -> network.
     */
    fun onPermissionsGranted() {
        viewModelScope.launch {
            // Step 1: Check root
            _uiState.value = _uiState.value.copy(step = StartupStep.CHECKING_ROOT)
            val hasRoot = rootChecker.isRootAvailable()
            _uiState.value = _uiState.value.copy(hasRoot = hasRoot)

            if (!hasRoot) {
                _uiState.value = _uiState.value.copy(
                    step = StartupStep.FAILED,
                    error = "Root access is required. Please root your device and grant su permissions.",
                )
                return@launch
            }

            // Step 2: Extract tools
            _uiState.value = _uiState.value.copy(step = StartupStep.EXTRACTING_TOOLS)

            // Collect extraction state updates in parallel
            val extractionJob = launch {
                toolManager.state.collect { state ->
                    _uiState.value = _uiState.value.copy(extractionState = state)
                }
            }

            toolManager.extractTools()

            val extractionResult = toolManager.state.value
            extractionJob.cancel()

            if (extractionResult is ExtractionState.Error) {
                _uiState.value = _uiState.value.copy(
                    step = StartupStep.FAILED,
                    error = extractionResult.message,
                )
                return@launch
            }

            // Step 2b: Extract Ruby+MSF (non-blocking, only if asset exists)
            if (!toolManager.isMsfInstalled()) {
                val rubyJob = launch {
                    toolManager.state.collect { state ->
                        _uiState.value = _uiState.value.copy(extractionState = state)
                    }
                }
                toolManager.extractRuby()
                rubyJob.cancel()
                // Ruby extraction failure is non-fatal — network tools work without MSF
                val rubyResult = toolManager.state.value
                if (rubyResult is ExtractionState.Error) {
                    Logger.warning("Ruby/MSF extraction failed (non-fatal): ${rubyResult.message}")
                }
            }

            // Step 3: Detect network
            _uiState.value = _uiState.value.copy(step = StartupStep.DETECTING_NETWORK)
            val networkInfo = networkManager.detectNetwork()

            if (networkInfo == null) {
                _uiState.value = _uiState.value.copy(
                    step = StartupStep.FAILED,
                    error = "Not connected to a WiFi network.",
                )
                return@launch
            }

            _uiState.value = _uiState.value.copy(
                step = StartupStep.READY,
                networkInfo = networkInfo,
            )

            Logger.info("Startup complete: ${networkInfo.ssid} (${networkInfo.localIp})")
        }
    }
}

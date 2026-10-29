package org.csploit.strix.ui.splash

import org.csploit.strix.domain.model.ExtractionState
import org.csploit.strix.domain.model.NetworkInfo

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

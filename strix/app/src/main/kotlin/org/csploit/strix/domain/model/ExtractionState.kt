package org.csploit.strix.domain.model

sealed class ExtractionState {
    data object Idle : ExtractionState()
    data object Checking : ExtractionState()
    data object AlreadyInstalled : ExtractionState()
    data class Extracting(val filesExtracted: Int, val currentFile: String) : ExtractionState()
    data object PatchingConfig : ExtractionState()
    data object Complete : ExtractionState()
    data class Error(val message: String) : ExtractionState()
}

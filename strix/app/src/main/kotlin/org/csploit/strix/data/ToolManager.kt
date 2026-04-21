package org.csploit.strix.data

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext
import org.csploit.strix.core.Logger
import org.csploit.strix.domain.model.ExtractionState
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ToolManager @Inject constructor(
    @ApplicationContext private val context: Context,
    private val toolsExtractor: ToolsExtractor,
    private val rubyExtractor: RubyExtractor,
) {
    private val _state = MutableStateFlow<ExtractionState>(ExtractionState.Idle)
    val state: StateFlow<ExtractionState> = _state

    val toolsPath: String get() = context.filesDir.absolutePath + "/tools/"
    val rubyPath: String get() = context.filesDir.absolutePath + "/ruby/"
    val msfPath: String get() = context.filesDir.absolutePath + "/msf/"
    val corePath: String get() = context.filesDir.absolutePath

    fun isToolsInstalled(): Boolean {
        val dir = toolsPath
        return File(dir, "bin/nmap").exists()
            && File(dir, "bin/hydra").exists()
            && File(dir, "bin/ettercap").exists()
            && File(dir, "bin/arpspoof").exists()
            && File(dir, "bin/tcpdump").exists()
            && File(dir, "lib/libettercap.so.0").exists()
    }

    fun isRubyInstalled(): Boolean = File(rubyPath, "bin/ruby").exists()

    fun isMsfInstalled(): Boolean = File(msfPath, "msfconsole").exists()

    suspend fun extractTools() = withContext(Dispatchers.IO) {
        if (isToolsInstalled()) {
            _state.value = ExtractionState.AlreadyInstalled
            return@withContext
        }

        _state.value = ExtractionState.Checking
        try {
            toolsExtractor.extract(context, _state)
            _state.value = ExtractionState.Complete
            Logger.info("ToolManager: tools extraction complete")
        } catch (e: Exception) {
            Logger.error("ToolManager: extraction failed: ${e.message}")
            _state.value = ExtractionState.Error("Tools extraction failed: ${e.message}")
        }
    }

    suspend fun extractRuby() = withContext(Dispatchers.IO) {
        if (isRubyInstalled() && isMsfInstalled()) {
            _state.value = ExtractionState.AlreadyInstalled
            return@withContext
        }

        _state.value = ExtractionState.Checking
        try {
            rubyExtractor.extract(context, _state)
            _state.value = ExtractionState.Complete
            Logger.info("ToolManager: ruby+msf extraction complete")
        } catch (e: Exception) {
            Logger.error("ToolManager: ruby extraction failed: ${e.message}")
            _state.value = ExtractionState.Error("Ruby extraction failed: ${e.message}")
        }
    }
}

package org.csploit.strix.ui.logs

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.csploit.strix.core.LogEntry
import org.csploit.strix.core.LogExporter
import org.csploit.strix.core.LogFormat
import org.csploit.strix.core.LogLevel
import org.csploit.strix.core.Logger
import javax.inject.Inject

enum class LevelFilter(val label: String, val minLevel: LogLevel) {
    ALL("All", LogLevel.DEBUG),
    INFO("Info+", LogLevel.INFO),
    WARN("Warn+", LogLevel.WARN),
    ERROR("Error", LogLevel.ERROR),
}

sealed interface LogsEvent {
    data class Share(val uri: Uri) : LogsEvent
    data class Message(val text: String) : LogsEvent
}

@HiltViewModel
class LogsViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
    private val exporter: LogExporter,
) : ViewModel() {

    private val entries = MutableStateFlow<List<LogEntry>>(emptyList())
    private val _filter = MutableStateFlow(LevelFilter.ALL)
    val filter: StateFlow<LevelFilter> = _filter.asStateFlow()
    private val _query = MutableStateFlow("")
    val query: StateFlow<String> = _query.asStateFlow()
    private val _loaded = MutableStateFlow(false)
    val loaded: StateFlow<Boolean> = _loaded.asStateFlow()

    val visible: StateFlow<List<LogEntry>> = combine(entries, _filter, _query) { all, f, q ->
        LogFormat.filter(all, f.minLevel, q)
    }.flowOn(Dispatchers.Default).stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    private val _events = Channel<LogsEvent>(Channel.BUFFERED)
    val events: Flow<LogsEvent> = _events.receiveAsFlow()

    init {
        // Re-read the files on every write batch, at most every RELOAD_MS (StateFlow is conflated).
        // Nothing here may call Logger: it would feed this loop.
        viewModelScope.launch {
            Logger.changes.collect {
                reload()
                delay(RELOAD_MS)
            }
        }
    }

    fun setFilter(value: LevelFilter) {
        _filter.value = value
    }

    fun setQuery(value: String) {
        _query.value = value
    }

    fun share() {
        viewModelScope.launch {
            runCatching { exporter.export() }
                .onSuccess { _events.send(LogsEvent.Share(it)) }
                .onFailure { _events.send(LogsEvent.Message("Export failed: ${it.message}")) }
        }
    }

    /** Copies the visible (filtered) lines, redacted, capped to fit the clipboard binder limit. */
    fun copy() {
        viewModelScope.launch {
            val text = withContext(Dispatchers.Default) {
                LogFormat.redact(visible.value.joinToString("\n") { it.toText() })
            }
            val clipped = if (text.length > MAX_CLIP_CHARS) text.takeLast(MAX_CLIP_CHARS) else text
            val clipboard = context.getSystemService(ClipboardManager::class.java)
            clipboard.setPrimaryClip(ClipData.newPlainText("Strix log", clipped))
            val note = if (clipped.length < text.length) " (last ${MAX_CLIP_CHARS / 1000}k chars; use Share for all)" else ""
            _events.send(LogsEvent.Message("Copied ${visible.value.size} lines$note"))
        }
    }

    fun clear() {
        viewModelScope.launch {
            withContext(Dispatchers.IO) { Logger.clearLog() }
            reload()
        }
    }

    private suspend fun reload() {
        entries.value = withContext(Dispatchers.IO) { LogFormat.parse(Logger.readLog()) }
        _loaded.value = true
    }

    private companion object {
        const val RELOAD_MS = 500L
        const val MAX_CLIP_CHARS = 200_000
    }
}

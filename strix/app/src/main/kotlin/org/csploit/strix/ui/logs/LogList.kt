package org.csploit.strix.ui.logs

import androidx.compose.foundation.interaction.DragInteraction
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Modifier
import kotlinx.coroutines.launch
import org.csploit.strix.core.LogEntry

@Composable
internal fun LogList(entries: List<LogEntry>) {
    val listState = rememberLazyListState()
    // Follow the tail unless the user scrolled up; scrolling back to the bottom resumes it.
    var follow by remember { mutableStateOf(true) }
    LaunchedEffect(listState) {
        // Only user drags change [follow]; our own scrollToItem emits no drag interaction.
        var userScroll = false
        launch {
            listState.interactionSource.interactions.collect {
                if (it is DragInteraction.Start) {
                    userScroll = true
                    follow = false
                }
            }
        }
        snapshotFlow { listState.isScrollInProgress }.collect { scrolling ->
            if (!scrolling && userScroll) {
                userScroll = false
                follow = !listState.canScrollForward
            }
        }
    }
    LaunchedEffect(entries.size) {
        if (follow && entries.isNotEmpty()) listState.scrollToItem(entries.lastIndex)
    }
    LazyColumn(state = listState, modifier = Modifier.fillMaxSize()) {
        itemsIndexed(entries) { _, entry -> LogEntryRow(entry) }
    }
}

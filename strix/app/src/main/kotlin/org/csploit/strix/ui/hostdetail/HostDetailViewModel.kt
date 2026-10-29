package org.csploit.strix.ui.hostdetail

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.csploit.strix.data.RouterAnalyzer
import javax.inject.Inject

@HiltViewModel
class HostDetailViewModel @Inject constructor(
    savedStateHandle: SavedStateHandle,
    private val routerAnalyzer: RouterAnalyzer,
) : ViewModel() {

    val ip: String = savedStateHandle["ip"] ?: ""
    val mac: String? = savedStateHandle.get<String>("mac")?.takeIf { it.isNotEmpty() }
    val hostName: String? = savedStateHandle.get<String>("name")?.takeIf { it.isNotEmpty() }

    private val _manufacturer = MutableStateFlow<String?>(null)
    val manufacturer: StateFlow<String?> = _manufacturer.asStateFlow()

    init {
        // OUI database load is file I/O: done off the main thread by OuiLookup.
        viewModelScope.launch {
            _manufacturer.value = routerAnalyzer.identifyManufacturer(mac)
        }
    }
}

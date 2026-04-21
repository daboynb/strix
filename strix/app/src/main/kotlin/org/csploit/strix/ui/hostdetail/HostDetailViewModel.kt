package org.csploit.strix.ui.hostdetail

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import dagger.hilt.android.lifecycle.HiltViewModel
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
    val manufacturer: String? = routerAnalyzer.identifyManufacturer(mac)
}

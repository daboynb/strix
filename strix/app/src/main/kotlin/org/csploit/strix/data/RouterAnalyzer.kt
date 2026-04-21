package org.csploit.strix.data

import javax.inject.Inject
import javax.inject.Singleton

/**
 * Facade for host analysis — delegates to specialized components.
 */
@Singleton
class RouterAnalyzer @Inject constructor(
    val ouiLookup: OuiLookup,
    val httpProbe: HttpProbe,
    val credentialTester: CredentialTester,
) {
    fun identifyManufacturer(mac: String?): String? = ouiLookup.identify(mac)
}

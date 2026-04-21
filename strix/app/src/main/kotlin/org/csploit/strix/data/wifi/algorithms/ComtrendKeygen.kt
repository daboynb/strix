/*
 * This file is part of the dSploit.
 *
 * Copyleft of Simone Margaritelli aka evilsocket <evilsocket@gmail.com>
 *
 * dSploit is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * dSploit is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with dSploit.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.csploit.strix.data.wifi.algorithms

import org.csploit.strix.data.wifi.Keygen
import java.security.MessageDigest

class ComtrendKeygen(
    ssid: String, mac: String, level: Int, enc: String
) : Keygen(ssid, mac, level, enc) {

    private val ssidIdentifier: String = ssid.substring(ssid.length - 4)

    override fun getKeys(): List<String>? {
        val md: MessageDigest = try {
            MessageDigest.getInstance("MD5")
        } catch (e: Exception) {
            errorMessage = "This phone cannot process a MD5 hash."
            return null
        }
        val macAddr = this.mac
        if (macAddr.length != 12) {
            errorMessage = "The MAC address is invalid."
            return null
        }
        val macMod = macAddr.substring(0, 8) + ssidIdentifier
        md.reset()
        md.update(MAGIC.toByteArray(Charsets.US_ASCII))
        md.update(macMod.uppercase().toByteArray(Charsets.US_ASCII))
        md.update(macAddr.uppercase().toByteArray(Charsets.US_ASCII))
        val hash = md.digest()
        addPassword(getHexString(hash).substring(0, 20))
        return getResults()
    }

    companion object {
        private const val MAGIC = "bcgbghgg"
    }
}

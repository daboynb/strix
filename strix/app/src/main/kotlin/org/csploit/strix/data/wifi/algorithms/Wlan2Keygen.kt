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

/**
 * Only calculates keys for some WLAN_xx.
 * Many WLAN_XX don't use this algorithm.
 * Code by Kampanita.
 */
class Wlan2Keygen(
    ssid: String, mac: String, level: Int, enc: String
) : Keygen(ssid, mac, level, enc) {

    private val ssidIdentifier: String = ssid.substring(ssid.length - 2)

    override fun getKeys(): List<String>? {
        val m = this.mac
        if (m.length != 12) {
            errorMessage = "The MAC address is invalid."
            return null
        }
        val key = CharArray(26)
        key[0]  = m[10]; key[1]  = m[11]
        key[2]  = m[0];  key[3]  = m[1]
        key[4]  = m[8];  key[5]  = m[9]
        key[6]  = m[2];  key[7]  = m[3]
        key[8]  = m[4];  key[9]  = m[5]
        key[10] = m[6];  key[11] = m[7]
        key[12] = m[10]; key[13] = m[11]
        key[14] = m[8];  key[15] = m[9]
        key[16] = m[2];  key[17] = m[3]
        key[18] = m[4];  key[19] = m[5]
        key[20] = m[6];  key[21] = m[7]
        key[22] = m[0];  key[23] = m[1]
        key[24] = m[4];  key[25] = m[5]

        val max = 9
        val begin = ssidIdentifier.substring(0, 1)
        val primerN = Integer.parseInt(begin, 16)
        if (primerN > max) {
            val cadena = String(key, 0, 2)
            var value = Integer.parseInt(cadena, 16)
            value -= 1
            var cadena2 = Integer.toHexString(value)
            if (cadena2.length < 2) cadena2 = "0$cadena2"
            key[0] = cadena2[0]
            key[1] = cadena2[1]
        }

        addPassword(String(key, 0, 26))
        return getResults()
    }
}

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
 * D-Link WPA key recovery.
 * Link: http://fodi.me/codigo-fonte-wpa-dlink-php-c/
 */
class DlinkKeygen(
    ssid: String, mac: String, level: Int, enc: String
) : Keygen(ssid, mac, level, enc) {

    override fun getKeys(): List<String>? {
        if (this.mac.isEmpty()) {
            errorMessage = "This key cannot be generated without MAC address."
            return null
        }
        val key = CharArray(20)
        val macAddr = this.mac

        key[0]  = macAddr[11]; key[1]  = macAddr[0]
        key[2]  = macAddr[10]; key[3]  = macAddr[1]
        key[4]  = macAddr[9];  key[5]  = macAddr[2]
        key[6]  = macAddr[8];  key[7]  = macAddr[3]
        key[8]  = macAddr[7];  key[9]  = macAddr[4]
        key[10] = macAddr[6];  key[11] = macAddr[5]
        key[12] = macAddr[1];  key[13] = macAddr[6]
        key[14] = macAddr[8];  key[15] = macAddr[9]
        key[16] = macAddr[11]; key[17] = macAddr[2]
        key[18] = macAddr[4];  key[19] = macAddr[10]

        val newkey = CharArray(20)
        for (i in 0 until 20) {
            val t = key[i]
            val index: Int = when {
                t in '0'..'9' -> t - '0'
                t.uppercaseChar() in 'A'..'F' -> t.uppercaseChar() - 'A' + 10
                else -> {
                    errorMessage = "Error in the calculation of the D-Link key."
                    return null
                }
            }
            newkey[i] = HASH[index]
        }
        addPassword(String(newkey, 0, 20))
        return getResults()
    }

    companion object {
        private val HASH = charArrayOf(
            'X', 'r', 'q', 'a', 'H', 'N',
            'p', 'd', 'S', 'Y', 'w',
            '8', '6', '2', '1', '5'
        )
    }
}

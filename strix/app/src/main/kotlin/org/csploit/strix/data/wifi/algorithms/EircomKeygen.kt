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

/**
 * Eircom WEP key algorithm.
 * Published at: http://www.bacik.org/eircomwep/howto.html
 */
class EircomKeygen(
    ssid: String, mac: String, level: Int, enc: String
) : Keygen(ssid, mac, level, enc) {

    override fun getKeys(): List<String>? {
        val macSuffix = this.mac.substring(6)
        val md: MessageDigest = try {
            MessageDigest.getInstance("SHA-1")
        } catch (e: Exception) {
            errorMessage = "This phone cannot process a SHA1 hash."
            return null
        }

        val routerMAC = ByteArray(4)
        routerMAC[0] = 1
        for (i in 0 until 6 step 2)
            routerMAC[i / 2 + 1] = ((Character.digit(macSuffix[i], 16) shl 4) +
                    Character.digit(macSuffix[i + 1], 16)).toByte()

        val macDec = ((0xFF and routerMAC[0].toInt()) shl 24) or
                ((0xFF and routerMAC[1].toInt()) shl 16) or
                ((0xFF and routerMAC[2].toInt()) shl 8) or
                (0xFF and routerMAC[3].toInt())

        val input = dectoString(macDec) + "Although your world wonders me, "
        md.reset()
        md.update(input.toByteArray())
        val hash = md.digest()
        addPassword(getHexString(hash).substring(0, 26))
        return getResults()
    }
}

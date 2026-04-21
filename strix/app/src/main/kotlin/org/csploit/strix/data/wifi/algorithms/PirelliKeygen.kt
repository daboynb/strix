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

class PirelliKeygen(
    ssid: String, mac: String, level: Int, enc: String
) : Keygen(ssid, mac, level, enc) {

    private val ssidIdentifier: String = ssid.substring(ssid.length - 12)

    override fun getKeys(): List<String>? {
        val md: MessageDigest = try {
            MessageDigest.getInstance("MD5")
        } catch (e: Exception) {
            errorMessage = "This phone cannot process a MD5 hash."
            return null
        }
        if (ssidIdentifier.length != 12) {
            errorMessage = "The MAC address is invalid."
            return null
        }

        val routerESSID = ByteArray(6)
        for (i in 0 until 12 step 2)
            routerESSID[i / 2] = ((Character.digit(ssidIdentifier[i], 16) shl 4) +
                    Character.digit(ssidIdentifier[i + 1], 16)).toByte()

        md.reset()
        md.update(routerESSID)
        md.update(SALT_MD5)
        val hash = md.digest()

        // Grouping in five groups of five bits
        val key = ShortArray(5)
        key[0] = ((hash[0].toInt() and 0xF8) shr 3).toShort()
        key[1] = (((hash[0].toInt() and 0x07) shl 2) or ((hash[1].toInt() and 0xC0) shr 6)).toShort()
        key[2] = ((hash[1].toInt() and 0x3E) shr 1).toShort()
        key[3] = (((hash[1].toInt() and 0x01) shl 4) or ((hash[2].toInt() and 0xF0) shr 4)).toShort()
        key[4] = (((hash[2].toInt() and 0x0F) shl 1) or ((hash[3].toInt() and 0x80) shr 7)).toShort()

        for (i in 0 until 5)
            if (key[i] >= 0x0A) key[i] = (key[i] + 0x57).toShort()

        addPassword(getHexString(key))
        return getResults()
    }

    companion object {
        private val SALT_MD5 = byteArrayOf(
            0x22, 0x33, 0x11, 0x34, 0x02,
            0x81.toByte(), 0xFA.toByte(), 0x22, 0x11, 0x41,
            0x68, 0x11, 0x12, 0x01, 0x05,
            0x22, 0x71, 0x42, 0x10, 0x66
        )
    }
}

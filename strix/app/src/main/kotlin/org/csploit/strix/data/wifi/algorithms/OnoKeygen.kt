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
 * Ono WiFi WEP key generation.
 * SSID form: [pP]1XXXXXX0000X
 *
 * Algorithm: increment last digit, use as passphrase for WEP keygen.
 * Produces both 64-bit and 128-bit WEP key candidates.
 *
 * Credit: pulido from http://foro.elhacker.net
 */
class OnoKeygen(
    ssid: String, mac: String, level: Int, enc: String
) : Keygen(ssid, mac, level, enc) {

    override fun getKeys(): List<String>? {
        if (this.ssid.length != 13) {
            errorMessage = "Invalid ESSID! It must have 13 characters."
            return null
        }
        var valStr = this.ssid.substring(0, 11) +
                (this.ssid.substring(11).toInt() + 1).toString()
        if (valStr.length < 13)
            valStr = this.ssid.substring(0, 11) + "0" + this.ssid.substring(11)

        val pseed = IntArray(4)
        for (i in valStr.indices) {
            pseed[i % 4] = pseed[i % 4] xor valStr[i].code
        }
        var randNumber = pseed[0] or (pseed[1] shl 8) or (pseed[2] shl 16) or (pseed[3] shl 24)

        // 64-bit WEP key (5 bytes)
        var key = ""
        for (j in 0 until 5) {
            randNumber = (randNumber * 0x343fd + 0x269ec3) and 0xffffffff.toInt()
            val tmp = ((randNumber shr 16) and 0xff).toShort()
            key += getHexString(tmp).uppercase()
        }
        addPassword(key)

        // 128-bit WEP key (13 bytes via MD5)
        key = ""
        val md: MessageDigest = try {
            MessageDigest.getInstance("MD5")
        } catch (e: Exception) {
            errorMessage = "This phone cannot process a MD5 hash"
            return null
        }
        md.reset()
        md.update(padto64(valStr).toByteArray())
        val hash = md.digest()
        for (i in 0 until 13)
            key += getHexString(hash[i].toShort())
        addPassword(key.uppercase())
        return getResults()
    }

    private fun padto64(v: String): String {
        if (v.isEmpty()) return ""
        val sb = StringBuilder()
        for (i in 0..64 / v.length) sb.append(v)
        return sb.substring(0, 64)
    }
}

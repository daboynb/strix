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

class Wlan6Keygen(
    ssid: String, mac: String, level: Int, enc: String
) : Keygen(ssid, mac, level, enc) {

    private val ssidIdentifier: String = ssid.substring(ssid.length - 6)

    override fun getKeys(): List<String>? {
        if (this.mac.isEmpty()) {
            errorMessage = "This key cannot be generated without MAC address."
            return null
        }
        val macStr = this.mac
        // Note: the original Java uses macStr.charAt(15) and charAt(16),
        // which references the BSSID with colons (17 chars). We use displayMac.
        val fullMac = displayMac
        val ssidSubPart = CharArray(6)
        val bssidLastByte = CharArray(2)

        ssidSubPart[0] = ssidIdentifier[0]
        ssidSubPart[1] = ssidIdentifier[1]
        ssidSubPart[2] = ssidIdentifier[2]
        ssidSubPart[3] = ssidIdentifier[3]
        ssidSubPart[4] = ssidIdentifier[4]
        ssidSubPart[5] = ssidIdentifier[5]
        bssidLastByte[0] = fullMac[15]
        bssidLastByte[1] = fullMac[16]

        for (k in 0 until 6)
            if (ssidSubPart[k] >= 'A')
                ssidSubPart[k] = (ssidSubPart[k].code - 55).toChar()

        if (bssidLastByte[0] >= 'A')
            bssidLastByte[0] = (bssidLastByte[0].code - 55).toChar()
        if (bssidLastByte[1] >= 'A')
            bssidLastByte[1] = (bssidLastByte[1].code - 55).toChar()

        for (i in 0 until 10) {
            /* Do not change the order of these instructions */
            val aux = i + (ssidSubPart[3].code and 0xf) + (bssidLastByte[0].code and 0xf) + (bssidLastByte[1].code and 0xf)
            val aux1 = (ssidSubPart[1].code and 0xf) + (ssidSubPart[2].code and 0xf) + (ssidSubPart[4].code and 0xf) + (ssidSubPart[5].code and 0xf)
            val second = aux xor (ssidSubPart[5].code and 0xf)
            val sixth = aux xor (ssidSubPart[4].code and 0xf)
            val tenth = aux xor (ssidSubPart[3].code and 0xf)
            val third = aux1 xor (ssidSubPart[2].code and 0xf)
            val seventh = aux1 xor (bssidLastByte[0].code and 0xf)
            val eleventh = aux1 xor (bssidLastByte[1].code and 0xf)
            val fourth = (bssidLastByte[0].code and 0xf) xor (ssidSubPart[5].code and 0xf)
            val eighth = (bssidLastByte[1].code and 0xf) xor (ssidSubPart[4].code and 0xf)
            val twelfth = aux xor aux1
            val fifth = second xor eighth
            val ninth = seventh xor eleventh
            val thirteenth = third xor tenth
            val first = twelfth xor sixth

            val key = Integer.toHexString(first and 0xf) +
                    Integer.toHexString(second and 0xf) +
                    Integer.toHexString(third and 0xf) +
                    Integer.toHexString(fourth and 0xf) +
                    Integer.toHexString(fifth and 0xf) +
                    Integer.toHexString(sixth and 0xf) +
                    Integer.toHexString(seventh and 0xf) +
                    Integer.toHexString(eighth and 0xf) +
                    Integer.toHexString(ninth and 0xf) +
                    Integer.toHexString(tenth and 0xf) +
                    Integer.toHexString(eleventh and 0xf) +
                    Integer.toHexString(twelfth and 0xf) +
                    Integer.toHexString(thirteenth and 0xf)
            addPassword(key.uppercase())
        }

        if ((ssidSubPart[0] != fullMac[10] || ssidSubPart[1] != fullMac[12] || ssidSubPart[2] != fullMac[13])
            && !this.ssid.startsWith("WiFi")
        ) {
            errorMessage = "The calculated SSID does not match the provided one."
        }
        return getResults()
    }
}

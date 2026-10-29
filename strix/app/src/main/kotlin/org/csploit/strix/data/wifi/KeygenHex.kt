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
package org.csploit.strix.data.wifi

/** Lowercase hex encoding behind [Keygen.getHexString]. */
internal object KeygenHex {

    private val HEX_CHAR_TABLE = byteArrayOf(
        '0'.code.toByte(), '1'.code.toByte(), '2'.code.toByte(), '3'.code.toByte(),
        '4'.code.toByte(), '5'.code.toByte(), '6'.code.toByte(), '7'.code.toByte(),
        '8'.code.toByte(), '9'.code.toByte(), 'a'.code.toByte(), 'b'.code.toByte(),
        'c'.code.toByte(), 'd'.code.toByte(), 'e'.code.toByte(), 'f'.code.toByte()
    )

    fun of(raw: ByteArray): String {
        val hex = ByteArray(2 * raw.size)
        var index = 0
        for (b in raw) {
            val v = b.toInt() and 0xFF
            hex[index++] = HEX_CHAR_TABLE[v ushr 4]
            hex[index++] = HEX_CHAR_TABLE[v and 0xF]
        }
        return String(hex, Charsets.US_ASCII)
    }

    fun of(raw: ShortArray): String {
        val hex = ByteArray(2 * raw.size)
        var index = 0
        for (b in raw) {
            val v = b.toInt() and 0xFF
            hex[index++] = HEX_CHAR_TABLE[v ushr 4]
            hex[index++] = HEX_CHAR_TABLE[v and 0xF]
        }
        return String(hex, Charsets.US_ASCII)
    }

    fun of(raw: Short): String {
        val hex = ByteArray(2)
        val v = raw.toInt() and 0xFF
        hex[0] = HEX_CHAR_TABLE[v ushr 4]
        hex[1] = HEX_CHAR_TABLE[v and 0xF]
        return String(hex, Charsets.US_ASCII)
    }
}

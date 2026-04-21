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

import java.security.MessageDigest

/**
 * Abstract base class for WiFi key generation algorithms.
 *
 * Each concrete subclass implements [getKeys] to compute candidate
 * default passwords for a specific router family.
 */
abstract class Keygen(
    val ssid: String,
    private val bssid: String,
    val level: Int,
    val encryption: String
) : Comparable<Keygen> {

    /** MAC address without colons, uppercased. */
    val mac: String get() = bssid.replace(":", "").uppercase()

    /** Original BSSID as passed in (with colons). */
    val displayMac: String get() = bssid

    @Volatile
    var stopRequested: Boolean = false

    var errorMessage: String? = null

    private val pwList = mutableListOf<String>()

    /** Accumulated password results (deduplicated). */
    fun getResults(): List<String> = pwList.toList()

    protected fun addPassword(key: String) {
        if (key !in pwList) pwList.add(key)
    }

    /** Compute candidate default keys for this network. Null on error. */
    abstract fun getKeys(): List<String>?

    /** Override to return false if this network cannot be processed. */
    open fun isSupported(): Boolean = true

    val isLocked: Boolean
        get() = getSecurity(encryption) != OPEN

    override fun compareTo(other: Keygen): Int {
        if (isSupported() && other.isSupported()) {
            return if (other.level == level) ssid.compareTo(other.ssid)
            else other.level - level
        }
        return if (isSupported()) -1 else 1
    }

    companion object {
        const val PSK = "PSK"
        const val WEP = "WEP"
        const val EAP = "EAP"
        const val OPEN = "Open"

        fun getSecurity(capabilities: String): String {
            val modes = arrayOf(WEP, PSK, EAP)
            for (i in modes.indices.reversed()) {
                if (capabilities.contains(modes[i])) return modes[i]
            }
            return OPEN
        }

        /**
         * Convert an integer to its English digit-name representation.
         * E.g. 123 -> "OneTwoThree"
         */
        fun dectoString(mac: Int): String {
            val names = arrayOf(
                "Zero", "One", "Two", "Three", "Four",
                "Five", "Six", "Seven", "Eight", "Nine"
            )
            var ret = ""
            var v = mac
            while (v > 0) {
                ret = names[v % 10] + ret
                v /= 10
            }
            return ret
        }

        private val HEX_CHAR_TABLE = byteArrayOf(
            '0'.code.toByte(), '1'.code.toByte(), '2'.code.toByte(), '3'.code.toByte(),
            '4'.code.toByte(), '5'.code.toByte(), '6'.code.toByte(), '7'.code.toByte(),
            '8'.code.toByte(), '9'.code.toByte(), 'a'.code.toByte(), 'b'.code.toByte(),
            'c'.code.toByte(), 'd'.code.toByte(), 'e'.code.toByte(), 'f'.code.toByte()
        )

        fun getHexString(raw: ByteArray): String {
            val hex = ByteArray(2 * raw.size)
            var index = 0
            for (b in raw) {
                val v = b.toInt() and 0xFF
                hex[index++] = HEX_CHAR_TABLE[v ushr 4]
                hex[index++] = HEX_CHAR_TABLE[v and 0xF]
            }
            return String(hex, Charsets.US_ASCII)
        }

        fun getHexString(raw: ShortArray): String {
            val hex = ByteArray(2 * raw.size)
            var index = 0
            for (b in raw) {
                val v = b.toInt() and 0xFF
                hex[index++] = HEX_CHAR_TABLE[v ushr 4]
                hex[index++] = HEX_CHAR_TABLE[v and 0xF]
            }
            return String(hex, Charsets.US_ASCII)
        }

        fun getHexString(raw: Short): String {
            val hex = ByteArray(2)
            val v = raw.toInt() and 0xFF
            hex[0] = HEX_CHAR_TABLE[v ushr 4]
            hex[1] = HEX_CHAR_TABLE[v and 0xF]
            return String(hex, Charsets.US_ASCII)
        }

        /** Convenience: compute MD5 digest. */
        fun md5(data: ByteArray): ByteArray =
            MessageDigest.getInstance("MD5").digest(data)

        /** Convenience: compute SHA-1 digest. */
        fun sha1(data: ByteArray): ByteArray =
            MessageDigest.getInstance("SHA-1").digest(data)

        /** Convenience: compute SHA-256 digest. */
        fun sha256(data: ByteArray): ByteArray =
            MessageDigest.getInstance("SHA-256").digest(data)
    }
}

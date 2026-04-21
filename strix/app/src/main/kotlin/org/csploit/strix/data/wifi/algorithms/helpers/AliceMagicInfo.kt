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
package org.csploit.strix.data.wifi.algorithms.helpers

/**
 * Magic info entry for Alice router keygen.
 *
 * @property alice  the Alice SSID prefix (e.g. "alice-123")
 * @property magic  two-element array: [q, k] used in serial derivation
 * @property serial the serial prefix string
 * @property mac    the default MAC address for this entry
 */
data class AliceMagicInfo(
    val alice: String,
    val magic: IntArray,
    val serial: String,
    val mac: String
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AliceMagicInfo) return false
        return alice == other.alice &&
                magic.contentEquals(other.magic) &&
                serial == other.serial &&
                mac == other.mac
    }

    override fun hashCode(): Int {
        var result = alice.hashCode()
        result = 31 * result + magic.contentHashCode()
        result = 31 * result + serial.hashCode()
        result = 31 * result + mac.hashCode()
        return result
    }
}

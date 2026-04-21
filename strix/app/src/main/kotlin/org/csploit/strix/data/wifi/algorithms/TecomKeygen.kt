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
 * Hitachi (TECOM) AH-4021 / AH-4222 WEP key algorithm.
 * Key = first 26 hex chars of SHA1(SSID).
 *
 * Link: http://rafale.org/~mattoufoutu/ebooks/Rafale-Mag/Rafale12/Rafale12.08.HTML
 */
class TecomKeygen(
    ssid: String, mac: String, level: Int, enc: String
) : Keygen(ssid, mac, level, enc) {

    override fun getKeys(): List<String>? {
        val md: MessageDigest = try {
            MessageDigest.getInstance("SHA-1")
        } catch (e: Exception) {
            errorMessage = "This phone cannot process a SHA1 hash."
            return null
        }
        md.reset()
        md.update(this.ssid.toByteArray())
        val hash = md.digest()
        addPassword(getHexString(hash).substring(0, 26))
        return getResults()
    }
}

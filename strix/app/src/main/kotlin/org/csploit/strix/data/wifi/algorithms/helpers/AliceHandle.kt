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

import org.xml.sax.Attributes
import org.xml.sax.helpers.DefaultHandler

/**
 * SAX handler that parses the Alice XML resource into a map of
 * SSID-prefix -> list of [AliceMagicInfo].
 */
class AliceHandle : DefaultHandler() {

    val supportedAlices: MutableMap<String, MutableList<AliceMagicInfo>> = mutableMapOf()

    override fun startElement(
        uri: String,
        localName: String,
        qName: String,
        attributes: Attributes
    ) {
        if (attributes.length == 0) return

        val supported = supportedAlices.getOrPut(qName) { mutableListOf() }
        val serial = attributes.getValue("sn") ?: ""
        val mac = attributes.getValue("mac") ?: ""
        val magic = intArrayOf(
            attributes.getValue("q")?.toInt() ?: 0,
            attributes.getValue("k")?.toInt() ?: 0
        )
        supported.add(AliceMagicInfo(qName, magic, serial, mac))
    }
}

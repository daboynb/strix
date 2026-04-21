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

import org.csploit.strix.data.wifi.algorithms.*
import org.csploit.strix.data.wifi.algorithms.helpers.AliceHandle
import org.csploit.strix.data.wifi.algorithms.helpers.AliceMagicInfo
import java.io.InputStream
import javax.xml.parsers.SAXParserFactory

/**
 * Matches a WiFi network (SSID + BSSID) to the appropriate keygen algorithm.
 *
 * Use the primary constructor with pre-parsed Alice data, or the companion
 * [fromXml] factory to parse from an InputStream.
 */
class WirelessMatcher(
    private val supportedAlices: Map<String, List<AliceMagicInfo>> = emptyMap()
) {
    companion object {
        /**
         * Parse Alice XML resource and create a WirelessMatcher.
         */
        fun fromXml(aliceXml: InputStream): WirelessMatcher {
            val aliceReader = AliceHandle()
            try {
                val factory = SAXParserFactory.newInstance()
                val saxParser = factory.newSAXParser()
                saxParser.parse(aliceXml, aliceReader)
            } catch (_: Exception) {
                // Alice entries will be empty
            }
            return WirelessMatcher(aliceReader.supportedAlices)
        }

        private val EASYBOX_MACS = setOf(
            "00:12:BF", "00:1A:2A", "00:1D:19", "00:23:08", "00:26:4D",
            "50:7E:5D", "1C:C6:3C", "74:31:70", "7C:4F:B5", "88:25:2C"
        )

        private val ZYXEL_MACS = setOf("00:1F:A4", "F4:3E:61", "40:4A:03")

        private val COMTREND_MACS = setOf(
            "00:1B:20", "64:68:0C", "00:1D:20", "00:23:F8", "38:72:C0", "30:39:F2"
        )

        private val SKY_MACS = setOf(
            "C4:3D:C7", "E0:46:9A", "E0:91:F5", "00:09:5B", "00:0F:B5",
            "00:14:6C", "00:18:4D", "00:26:F2", "C0:3F:0E", "30:46:9A",
            "00:1B:2F", "A0:21:B7", "00:1E:2A", "00:1F:33", "00:22:3F",
            "00:24:B2"
        )

        private val WLAN2_MACS = setOf(
            "00:01:38", "00:16:38", "00:01:13", "00:01:1B", "00:19:5B"
        )

        private val VERIZON_MACS = setOf(
            "00:1F:90", "A8:39:44", "00:18:01", "00:20:E0", "00:0F:B3",
            "00:1E:A7", "00:15:05", "00:24:7B", "00:26:62", "00:26:B8"
        )

        private val HUAWEI_MACS = setOf(
            "00:25:9E", "00:25:68", "00:22:A1", "00:1E:10", "00:18:82",
            "00:0F:F2", "00:E0:FC", "28:6E:D4", "54:A5:1B", "F4:C7:14",
            "28:5F:DB", "30:87:30", "4C:54:99", "40:4D:8E", "64:16:F0",
            "78:1D:BA", "84:A8:E4", "04:C0:6F", "5C:4C:A9", "1C:1D:67",
            "CC:96:A0", "20:2B:C1"
        )
    }

    fun getKeygen(ssid: String, bssid: String, level: Int, encryption: String): Keygen? {
        var mac = bssid.uppercase()
        var enc = encryption
        if (enc.isEmpty()) enc = Keygen.OPEN

        // Discus
        if (ssid.matches(Regex("Discus--?[0-9a-fA-F]{6}")))
            return DiscusKeygen(ssid, mac, level, enc)

        // Eircom
        if (ssid.matches(Regex("[eE]ircom[0-7]{4} ?[0-7]{4}"))) {
            if (mac.isEmpty() || mac.replace(":", "").isEmpty()) {
                val filteredSsid = ssid.replace(" ", "")
                val end = Integer.toHexString(
                    Integer.parseInt(filteredSsid.substring(filteredSsid.length - 8), 8) xor 0x000fcc
                )
                mac = "00:0F:CC:${end.substring(0, 2)}:${end.substring(2, 4)}:${end.substring(4, 6)}"
            }
            return EircomKeygen(ssid, mac, level, enc)
        }

        // EasyBox -- MUST be before Thomson because of overlapping SSIDs
        if (ssid.matches(Regex("(Arcor|EasyBox|Vodafone)(-| )[0-9a-fA-F]{6}")) &&
            EASYBOX_MACS.any { mac.startsWith(it) }
        ) {
            return EasyBoxKeygen(ssid, mac, level, enc)
        }

        // Thomson / SpeedTouch / O2 / Orange / INFINITUM / BigPond / etc.
        if (ssid.matches(Regex(
                "(Thomson|Blink|SpeedTouch|O2Wireless|Orange-|INFINITUM|" +
                        "BigPond|Otenet|Bbox-|DMAX|privat|TN_private_|CYTA|Vodafone-|Optimus|OptimusFibra|MEO-)[0-9a-fA-F]{6}"
            ))
        ) {
            return ThomsonKeygen(ssid, mac, level, enc)
        }

        // D-Link
        if (ssid.matches(Regex("DLink-[0-9a-fA-F]{6}")))
            return DlinkKeygen(ssid, mac, level, enc)

        // FASTWEB Pirelli
        if (ssid.matches(Regex(
                "FASTWEB-1-(000827|0013C8|0017C2|00193E|001CA2|001D8B|" +
                        "002233|00238E|002553|00A02F|080018|3039F2|38229D|6487D7)[0-9A-Fa-f]{6}"
            ))
        ) {
            if (mac.isEmpty() || mac.replace(":", "").isEmpty()) {
                val end = ssid.substring(ssid.length - 12)
                mac = "${end.substring(0, 2)}:${end.substring(2, 4)}:${end.substring(4, 6)}:" +
                        "${end.substring(6, 8)}:${end.substring(8, 10)}:${end.substring(10, 12)}"
            }
            return PirelliKeygen(ssid, mac, level, enc)
        }

        // FASTWEB Telsey
        if (ssid.matches(Regex("FASTWEB-(1|2)-(002196|00036F)[0-9A-Fa-f]{6}"))) {
            if (mac.isEmpty() || mac.replace(":", "").isEmpty()) {
                val end = ssid.substring(ssid.length - 12)
                mac = "${end.substring(0, 2)}:${end.substring(2, 4)}:${end.substring(4, 6)}:" +
                        "${end.substring(6, 8)}:${end.substring(8, 10)}:${end.substring(10, 12)}"
            }
            return TelseyKeygen(ssid, mac, level, enc)
        }

        // Alice
        if (ssid.matches(Regex("[aA]lice-[0-9]{8}"))) {
            val supported = supportedAlices[ssid.substring(0, 9)]
            if (!supported.isNullOrEmpty()) {
                var resolvedMac = mac
                if (resolvedMac.replace(":", "").length < 6) {
                    resolvedMac = supported[0].mac
                }
                return AliceKeygen(ssid, resolvedMac, level, enc, supported)
            }
        }

        // Ono
        if (ssid.matches(Regex("[Pp]1[0-9]{6}0{4}[0-9]")))
            return OnoKeygen(ssid, mac, level, enc)

        // WLAN / JAZZTEL with Zyxel or Comtrend
        if (ssid.matches(Regex("(WLAN|JAZZTEL)_[0-9a-fA-F]{4}"))) {
            if (ZYXEL_MACS.any { mac.startsWith(it) })
                return ZyxelKeygen(ssid, mac, level, enc)
            if (COMTREND_MACS.any { mac.startsWith(it) })
                return ComtrendKeygen(ssid, mac, level, enc)
        }

        // SKY v1
        if (ssid.matches(Regex("SKY[0-9]{5}")) && SKY_MACS.any { mac.startsWith(it) })
            return SkyV1Keygen(ssid, mac, level, enc)

        // TECOM
        if (ssid.matches(Regex("TECOM-AH4(021|222)-[0-9a-zA-Z]{6}")))
            return TecomKeygen(ssid, mac, level, enc)

        // Infostrada
        if (ssid.matches(Regex("InfostradaWiFi-[0-9a-zA-Z]{6}")))
            return InfostradaKeygen(ssid, mac, level, enc)

        // WLAN_XX (2-char suffix)
        if (ssid.startsWith("WLAN_") && ssid.length == 7 &&
            WLAN2_MACS.any { mac.startsWith(it) }
        ) {
            return Wlan2Keygen(ssid, mac, level, enc)
        }

        // WLAN/WiFi/YaCom + 6 chars
        if (ssid.matches(Regex("(WLAN|WiFi|YaCom)[0-9a-zA-Z]{6}")))
            return Wlan6Keygen(ssid, mac, level, enc)

        // OTE
        if (ssid.matches(Regex("OTE[0-9a-fA-F]{6}")))
            return OteKeygen(ssid, mac, level, enc)

        // PBS
        if (ssid.matches(Regex("PBS-[0-9a-fA-F]{6}")))
            return PBSKeygen(ssid, mac, level, enc)

        // CONN-X
        if (ssid == "CONN-X")
            return ConnKeygen(ssid, mac, level, enc)

        // Andared
        if (ssid == "Andared")
            return AndaredKeygen(ssid, mac, level, enc)

        // Megared
        if (ssid.matches(Regex("Megared[0-9a-fA-F]{4}"))) {
            val macNaked = mac.replace(":", "")
            if (macNaked.isEmpty() ||
                ssid.substring(ssid.length - 4).equals(macNaked.substring(8), ignoreCase = true)
            ) {
                return MegaredKeygen(ssid, mac, level, enc)
            }
        }

        // Verizon (5-char SSID + specific MACs)
        if (ssid.length == 5 && VERIZON_MACS.any { mac.startsWith(it) })
            return VerizonKeygen(ssid, mac, level, enc)

        // Huawei INFINITUM
        if (ssid.matches(Regex("INFINITUM[0-9a-zA-Z]{4}")) &&
            HUAWEI_MACS.any { mac.startsWith(it) }
        ) {
            return HuaweiKeygen(ssid, mac, level, enc)
        }

        return null
    }
}

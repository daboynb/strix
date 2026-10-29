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

/** BSSID prefixes (OUIs) [WirelessMatcher] requires for vendor-ambiguous SSIDs. */
internal object VendorMacs {
    val EASYBOX_MACS = setOf(
        "00:12:BF", "00:1A:2A", "00:1D:19", "00:23:08", "00:26:4D",
        "50:7E:5D", "1C:C6:3C", "74:31:70", "7C:4F:B5", "88:25:2C"
    )

    val ZYXEL_MACS = setOf("00:1F:A4", "F4:3E:61", "40:4A:03")

    val COMTREND_MACS = setOf(
        "00:1B:20", "64:68:0C", "00:1D:20", "00:23:F8", "38:72:C0", "30:39:F2"
    )

    val SKY_MACS = setOf(
        "C4:3D:C7", "E0:46:9A", "E0:91:F5", "00:09:5B", "00:0F:B5",
        "00:14:6C", "00:18:4D", "00:26:F2", "C0:3F:0E", "30:46:9A",
        "00:1B:2F", "A0:21:B7", "00:1E:2A", "00:1F:33", "00:22:3F",
        "00:24:B2"
    )

    val WLAN2_MACS = setOf(
        "00:01:38", "00:16:38", "00:01:13", "00:01:1B", "00:19:5B"
    )

    val VERIZON_MACS = setOf(
        "00:1F:90", "A8:39:44", "00:18:01", "00:20:E0", "00:0F:B3",
        "00:1E:A7", "00:15:05", "00:24:7B", "00:26:62", "00:26:B8"
    )

    val HUAWEI_MACS = setOf(
        "00:25:9E", "00:25:68", "00:22:A1", "00:1E:10", "00:18:82",
        "00:0F:F2", "00:E0:FC", "28:6E:D4", "54:A5:1B", "F4:C7:14",
        "28:5F:DB", "30:87:30", "4C:54:99", "40:4D:8E", "64:16:F0",
        "78:1D:BA", "84:A8:E4", "04:C0:6F", "5C:4C:A9", "1C:1D:67",
        "CC:96:A0", "20:2B:C1"
    )
}

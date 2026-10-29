package org.csploit.strix.ui.packetforger

/** Turn the typed `\r`, `\n`, `\t` escapes into real control characters. */
internal fun decodePayloadEscapes(payload: String): ByteArray = payload
    .replace("\\r", "\r")
    .replace("\\n", "\n")
    .replace("\\t", "\t")
    .toByteArray()

/** Hex form of a WoL magic packet, shown in the payload field. */
internal fun wolPayloadHex(mac: String): String {
    val m = mac.replace(":", "")
    return "FF".repeat(6) + m.uppercase().repeat(16)
}

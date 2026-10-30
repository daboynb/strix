package org.csploit.strix.data

/**
 * Decodes the HTML character references found in page titles: numeric
 * (`&#72;`, `&#x48;`) and the common named ones. Unknown or malformed
 * references are left as they are. Plain JVM code, so it is unit-testable.
 */
internal object HtmlEntities {
    private val REFERENCE = Regex("&(#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6}|[a-zA-Z]{2,8});")

    private val NAMED = mapOf(
        "amp" to "&", "lt" to "<", "gt" to ">", "quot" to "\"", "apos" to "'",
        "nbsp" to " ", "copy" to "©", "reg" to "®", "trade" to "™",
        "ndash" to "–", "mdash" to "—", "hellip" to "…", "middot" to "·",
    )

    fun decode(text: String): String = REFERENCE.replace(text) { m ->
        val ref = m.groupValues[1]
        val decoded = when {
            ref.startsWith("#x") || ref.startsWith("#X") -> codePoint(ref.substring(2).toIntOrNull(16))
            ref.startsWith("#") -> codePoint(ref.substring(1).toIntOrNull())
            else -> NAMED[ref]
        }
        decoded ?: m.value
    }

    private fun codePoint(cp: Int?): String? =
        if (cp == null || cp == 0 || !Character.isValidCodePoint(cp) || cp in 0xD800..0xDFFF) null
        else String(Character.toChars(cp))
}

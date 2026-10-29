package org.csploit.strix.data.bundle

import org.json.JSONException
import org.json.JSONObject

/**
 * Describes one native bundle archive. Produced by CI as `<bundle>.json`
 * (signed via `<bundle>.json.sig` for downloaded bundles) and stored verbatim
 * as `.bundle-version` inside the installed bundle's primary directory.
 */
data class BundleManifest(
    val format: Int,
    val id: String,
    val version: String,
    val file: String,
    val sha256: String,
    val size: Long,
    val unpacked: Long,
    val minApp: Int,
    /**
     * Build/signing time, UTC epoch seconds (`"built"`; an ISO-8601 string is
     * accepted too). Monotonic across releases, so it orders bundles whose
     * version strings aren't comparable. Null for manifests that predate it.
     */
    val built: Long? = null,
) {
    companion object {
        const val SUPPORTED_FORMAT = 1
        private val SHA256_HEX = Regex("^[0-9a-f]{64}$")
        private val SAFE_NAME = Regex("^[A-Za-z0-9._-]+$")

        /** Parse and validate; throws [IllegalArgumentException] on any malformed field. */
        fun parse(json: String): BundleManifest {
            val o = try {
                JSONObject(json)
            } catch (e: JSONException) {
                throw IllegalArgumentException("manifest is not valid JSON: ${e.message}")
            }
            val m = try {
                BundleManifest(
                    format = o.getInt("format"),
                    id = o.getString("id"),
                    version = o.getString("version"),
                    file = o.getString("file"),
                    sha256 = o.getString("sha256").lowercase(),
                    size = o.getLong("size"),
                    unpacked = o.getLong("unpacked"),
                    minApp = o.getInt("minApp"),
                    built = parseBuilt(o),
                )
            } catch (e: JSONException) {
                throw IllegalArgumentException("manifest field missing or invalid: ${e.message}")
            }
            require(m.format == SUPPORTED_FORMAT) { "unsupported manifest format ${m.format}" }
            require(m.id.matches(SAFE_NAME)) { "invalid bundle id '${m.id}'" }
            require(m.version.isNotBlank()) { "empty version" }
            require(m.file.matches(SAFE_NAME)) { "invalid file name '${m.file}'" }
            require(m.sha256.matches(SHA256_HEX)) { "invalid sha256" }
            require(m.size > 0) { "invalid size ${m.size}" }
            require(m.unpacked > 0) { "invalid unpacked size ${m.unpacked}" }
            require(m.minApp >= 0) { "invalid minApp ${m.minApp}" }
            require(m.built == null || m.built > 0) { "invalid built ${m.built}" }
            return m
        }

        private fun parseBuilt(o: JSONObject): Long? {
            if (!o.has("built") || o.isNull("built")) return null
            return when (val v = o.get("built")) {
                is Number -> v.toLong()
                is String -> try {
                    java.time.Instant.parse(v).epochSecond
                } catch (e: java.time.format.DateTimeParseException) {
                    throw IllegalArgumentException("invalid built '$v'")
                }
                else -> throw IllegalArgumentException("invalid built '$v'")
            }
        }

        /** Like [parse] but returns null instead of throwing. */
        fun parseOrNull(json: String?): BundleManifest? =
            json?.let { runCatching { parse(it) }.getOrNull() }
    }

    /** Same archive content (id + hash), regardless of formatting of the json. */
    fun sameContentAs(other: BundleManifest?): Boolean =
        other != null && other.id == id && other.sha256 == sha256
}

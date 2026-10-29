package org.csploit.strix.data.bundle

import org.json.JSONArray

data class ReleaseAsset(val name: String, val size: Long, val url: String)

/** The newest bundle release and the three assets it must carry. */
data class BundleRelease(
    val tag: String,
    val createdAt: String,
    val manifest: ReleaseAsset,
    val signature: ReleaseAsset,
    val assets: List<ReleaseAsset>,
) {
    fun asset(name: String): ReleaseAsset? = assets.firstOrNull { it.name == name }
}

/** Parses the GitHub REST `GET /repos/{owner}/{repo}/releases` response. */
object GitHubReleases {

    const val REPO = "daboynb/strix"
    const val RELEASES_URL = "https://api.github.com/repos/$REPO/releases?per_page=30"
    const val MSF_TAG_PREFIX = "bundles-msf-"
    const val TOOLS_TAG_PREFIX = "bundles-tools-"

    /**
     * Newest (by created_at) non-draft release whose tag starts with [tagPrefix]
     * and that has exactly one `.json` asset with a matching `.json.sig`.
     * Releases missing those are skipped. Returns null if none qualifies.
     */
    fun pickLatest(json: String, tagPrefix: String): BundleRelease? {
        val arr = JSONArray(json)
        val candidates = mutableListOf<BundleRelease>()
        for (i in 0 until arr.length()) {
            val r = arr.getJSONObject(i)
            if (r.optBoolean("draft", false)) continue
            val tag = r.optString("tag_name", "")
            if (!tag.startsWith(tagPrefix)) continue
            val assetsJson = r.optJSONArray("assets") ?: continue
            val assets = (0 until assetsJson.length()).map { j ->
                val a = assetsJson.getJSONObject(j)
                ReleaseAsset(a.optString("name"), a.optLong("size", -1), a.optString("browser_download_url"))
            }.filter { it.name.isNotEmpty() && it.url.isNotEmpty() }
            val manifests = assets.filter { it.name.endsWith(".json") }
            val manifest = manifests.singleOrNull() ?: continue
            val sig = assets.firstOrNull { it.name == manifest.name + ".sig" } ?: continue
            candidates += BundleRelease(tag, r.optString("created_at", ""), manifest, sig, assets)
        }
        // ISO-8601 UTC timestamps sort lexicographically.
        return candidates.maxByOrNull { it.createdAt }
    }
}

package org.csploit.strix.data.bundle

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities

/** [BundleEnv] backed by the Android system services and the GitHub releases API. */
internal class AndroidBundleEnv(
    private val context: Context,
    private val downloader: BundleDownloader,
) : BundleEnv {
    companion object {
        private const val MAX_API_BYTES = 2 * 1024 * 1024
    }

    override fun isOnWifi(): Boolean {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return false
        val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return false
        return caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
    }

    override fun appVersionCode(): Long =
        context.packageManager.getPackageInfo(context.packageName, 0).longVersionCode

    override fun fetchReleasesJson(): String = String(
        downloader.fetchBytes(GitHubReleases.RELEASES_URL, MAX_API_BYTES, "application/vnd.github+json"),
        Charsets.UTF_8,
    )
}

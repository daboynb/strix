package org.csploit.strix.data.bundle

import java.math.BigInteger

/** Ordering of bundle manifests (update offers, rollback protection, APK vs downloaded). */
object BundleVersions {

    /** Installed version reported for bundles extracted by older APKs (no `.bundle-version`). */
    const val LEGACY = "legacy"

    private val TOKEN = Regex("\\d+|[A-Za-z]+")

    /**
     * Compare dotted/dashed version strings token by token: numbers
     * numerically, words case-insensitively, a number beats a word, and extra
     * trailing tokens are newer ("6.4.125-r2" > "6.4.125-r1" > "6.4.125").
     * Only a tie-breaker: [compare] for manifests orders by `built` first.
     */
    fun compareVersions(a: String, b: String): Int {
        val ta = TOKEN.findAll(a).map { it.value }.toList()
        val tb = TOKEN.findAll(b).map { it.value }.toList()
        for (i in 0 until maxOf(ta.size, tb.size)) {
            val x = ta.getOrNull(i) ?: return -1
            val y = tb.getOrNull(i) ?: return 1
            val xn = x[0].isDigit()
            val yn = y[0].isDigit()
            val c = when {
                xn && yn -> BigInteger(x).compareTo(BigInteger(y))
                xn -> 1
                yn -> -1
                else -> x.compareTo(y, ignoreCase = true)
            }
            if (c != 0) return c
        }
        return 0
    }

    /**
     * Order two manifests of the same bundle: by `built` (a manifest without
     * it is older than any manifest with it); if both lack it or it is equal,
     * by version string.
     */
    fun compare(a: BundleManifest, b: BundleManifest): Int {
        val ba = a.built
        val bb = b.built
        return when {
            ba != null && bb != null && ba != bb -> ba.compareTo(bb)
            ba == null && bb != null -> -1
            ba != null && bb == null -> 1
            else -> compareVersions(a.version, b.version)
        }
    }

    /**
     * True if [candidate] should replace [installed]; null = not installed or
     * a legacy install without manifest (always replaceable). The same archive
     * is never "newer".
     */
    fun isNewer(candidate: BundleManifest, installed: BundleManifest?): Boolean =
        installed == null || (!candidate.sameContentAs(installed) && compare(candidate, installed) > 0)

    /**
     * Tools at app start: install the APK copy unless the installed bundle is
     * usable and either the same archive or strictly newer (a downloaded update
     * newer than the APK must survive app updates). An installed manifest
     * without `built` predates ordering and always yields to the APK copy.
     */
    fun shouldInstallApkCopy(apk: BundleManifest, installed: BundleManifest?, sentinelsOk: Boolean): Boolean = when {
        !sentinelsOk || installed == null -> true
        apk.sameContentAs(installed) -> false
        installed.built == null -> true
        else -> compare(installed, apk) <= 0
    }
}

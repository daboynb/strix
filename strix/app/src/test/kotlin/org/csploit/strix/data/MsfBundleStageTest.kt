package org.csploit.strix.data

import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * Not a regular unit test: a hook for the emulator msf test (scripts/emulator-msf-test.sh),
 * skipped unless STRIX_MSF_STAGE is set. It applies the app's real post-install patches
 * ([MsfBundlePatches.fixGemPaths]: extension symlinks, nokogiri link, msfrpcd wrapper) to
 * an extracted bundle laid out as the app installs it (`<stage>/msf`, `<stage>/ruby`),
 * so the emulator runs exactly what a device would, without a copy of that logic.
 */
class MsfBundleStageTest {

    @Test
    fun patchStagedBundle() {
        val stage = System.getenv("STRIX_MSF_STAGE")
        assumeTrue("STRIX_MSF_STAGE not set", !stage.isNullOrEmpty())
        val msf = File(stage!!, "msf")
        val ruby = File(stage, "ruby")
        check(msf.isDirectory && ruby.isDirectory) { "expected $stage/msf and $stage/ruby" }
        MsfBundlePatches.fixGemPaths(msf, ruby)
    }
}

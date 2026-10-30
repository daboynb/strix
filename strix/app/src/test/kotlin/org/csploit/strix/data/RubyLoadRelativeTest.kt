package org.csploit.strix.data

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class RubyLoadRelativeTest {
    @get:Rule val tmp = TemporaryFolder()

    private fun ruby(relative: String?): File {
        val ruby = tmp.newFolder("ruby")
        val arch = File(ruby, "lib/ruby/3.3.0/aarch64-linux-android-android").apply { mkdirs() }
        if (relative != null) File(arch, "rbconfig.rb").writeText("  CONFIG[\"LIBRUBY_RELATIVE\"] = \"$relative\"\n")
        return ruby
    }

    @Test
    fun loadRelativeBuildIsDetected() = assertTrue(RubyExtractor.isLoadRelative(ruby("yes")))

    @Test
    fun absolutePathsBuildIsNot() = assertFalse(RubyExtractor.isLoadRelative(ruby("no")))

    @Test
    fun missingRbconfigIsNot() = assertFalse(RubyExtractor.isLoadRelative(ruby(null)))
}

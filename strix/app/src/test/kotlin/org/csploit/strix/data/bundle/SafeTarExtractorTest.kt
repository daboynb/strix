package org.csploit.strix.data.bundle

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.nio.file.Files

class SafeTarExtractorTest {
    @get:Rule val tmp = TemporaryFolder()

    private fun extract(t: TarFixture, root: File = File(tmp.root, "root")) =
        SafeTarExtractor.extract(t.build().inputStream(), root)

    private fun assertRejected(t: TarFixture) {
        try {
            extract(t)
            fail("expected UnsafeEntryException")
        } catch (_: SafeTarExtractor.UnsafeEntryException) {
        }
        assertFalse("nothing written outside root", File(tmp.root, "evil").exists())
    }

    @Test fun extractsFilesDirsAndInternalSymlinks() {
        val root = File(tmp.root, "root")
        val n = extract(
            TarFixture().dir("bin").file("bin/tool", "x", mode = 0b111_101_101).file("./lib/a.so", "a")
                .symlink("lib/b.so", "a.so").hardlink("lib/c.so", "lib/a.so"),
            root,
        )
        assertEquals(4, n)
        assertTrue(File(root, "bin/tool").canExecute())
        assertEquals("a", File(root, "lib/b.so").readText())
        assertTrue(Files.isSymbolicLink(File(root, "lib/b.so").toPath()))
        assertEquals("a", File(root, "lib/c.so").readText())
        assertFalse(Files.isSymbolicLink(File(root, "lib/c.so").toPath()))
    }

    @Test fun rejectsParentTraversal() = assertRejected(TarFixture().file("../evil", "x"))

    @Test fun rejectsNestedParentTraversal() = assertRejected(TarFixture().file("a/../../evil", "x"))

    @Test fun rejectsAbsolutePath() {
        val target = File(tmp.root, "evil")
        assertRejected(TarFixture().file(target.absolutePath, "x"))
    }

    @Test fun rejectsAbsoluteSymlink() = assertRejected(TarFixture().symlink("link", File(tmp.root, "evil").absolutePath))

    @Test fun rejectsSymlinkEscapingRoot() = assertRejected(TarFixture().symlink("a/link", "../../evil"))

    @Test fun rejectsWriteThroughEscapingSymlinkChain() {
        // d -> e/.. looks inside lexically, but once e -> "." exists it resolves to root/..
        assertRejected(TarFixture().symlink("d", "e/..").symlink("e", ".").file("d/evil", "x"))
    }

    @Test fun rejectsHardlinkOutsideRoot() = assertRejected(TarFixture().hardlink("x", "../evil"))

    @Test fun mapPathSkipsAndRelocates() {
        val root = File(tmp.root, "root")
        SafeTarExtractor.extract(
            TarFixture().file("ruby-android/bin/ruby").file("junk/file").build().inputStream(),
            root,
            mapPath = { if (it.startsWith("ruby-android/")) "ruby/" + it.removePrefix("ruby-android/") else null },
        )
        assertTrue(File(root, "ruby/bin/ruby").isFile)
        assertFalse(File(root, "junk").exists())
    }
}

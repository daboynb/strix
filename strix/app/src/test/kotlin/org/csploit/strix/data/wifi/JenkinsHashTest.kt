package org.csploit.strix.data.wifi

import org.csploit.strix.data.wifi.algorithms.helpers.JenkinsHash
import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.Random

/**
 * Compares [JenkinsHash.hashword] (Long-based uint32 emulation) against a
 * straight Int port of Bob Jenkins' lookup3 hashword(), where Int overflow
 * gives the native uint32 wrap-around.
 */
class JenkinsHashTest {

    private fun rot(x: Int, k: Int): Int = (x shl k) or (x ushr (32 - k))

    private fun referenceHashword(k: IntArray, length: Int, initval: Int): Int {
        var a = 0xdeadbeef.toInt() + (length shl 2) + initval
        var b = a
        var c = a
        var len = length
        var i = 0
        while (len > 3) {
            a += k[i]; b += k[i + 1]; c += k[i + 2]
            a -= c; a = a xor rot(c, 4); c += b
            b -= a; b = b xor rot(a, 6); a += c
            c -= b; c = c xor rot(b, 8); b += a
            a -= c; a = a xor rot(c, 16); c += b
            b -= a; b = b xor rot(a, 19); a += c
            c -= b; c = c xor rot(b, 4); b += a
            len -= 3
            i += 3
        }
        if (len == 0) return c
        if (len == 3) c += k[i + 2]
        if (len >= 2) b += k[i + 1]
        a += k[i]
        c = c xor b; c -= rot(b, 14)
        a = a xor c; a -= rot(c, 11)
        b = b xor a; b -= rot(a, 25)
        c = c xor b; c -= rot(b, 16)
        a = a xor c; a -= rot(c, 4)
        b = b xor a; b -= rot(a, 14)
        c = c xor b; c -= rot(b, 24)
        return c
    }

    private fun assertMatches(k: IntArray, length: Int, initval: Int) {
        val expected = referenceHashword(k, length, initval).toLong() and 0xFFFFFFFFL
        val actual = JenkinsHash().hashword(
            LongArray(k.size) { k[it].toLong() and 0xFFFFFFFFL },
            length,
            initval.toLong() and 0xFFFFFFFFL,
        )
        assertEquals(
            "length=$length initval=${Integer.toHexString(initval)}",
            expected,
            actual,
        )
    }

    @Test
    fun emptyInputReturnsInitialState() {
        assertEquals(0xdeadbeefL, JenkinsHash().hashword(LongArray(0), 0, 0))
    }

    @Test
    fun seedDeadbeefWrapsAt32Bits() {
        // 0xdeadbeef + 0xdeadbeef overflows 32 bits: the case the unmasked
        // initial sum got wrong.
        val k = intArrayOf(0x12345678, 0x9abcdef0.toInt(), 0x0fedcba9, 0x87654321.toInt())
        for (length in 0..k.size) assertMatches(k, length, 0xDEADBEEF.toInt())
    }

    @Test
    fun matchesReferenceOnRandomInputs() {
        val rnd = Random(42)
        val seeds = intArrayOf(0, 1, 0xDEADBEEF.toInt(), 0x7FFFFFFF, -1)
        repeat(200) {
            val k = IntArray(rnd.nextInt(14)) { rnd.nextInt() }
            for (seed in seeds + rnd.nextInt()) assertMatches(k, k.size, seed)
        }
    }

    @Test
    fun matchesReferenceForTelseyStyleSeedChaining() {
        // TelseyKeygen feeds each result back as the next seed over a 64-word key.
        val rnd = Random(7)
        val k = IntArray(64) { rnd.nextInt() }
        val longKey = LongArray(64) { k[it].toLong() and 0xFFFFFFFFL }
        val hash = JenkinsHash()
        var seed = 0L
        var refSeed = 0
        for (x in 0 until 64) {
            seed = hash.hashword(longKey, x, seed)
            refSeed = referenceHashword(k, x, refSeed)
            assertEquals("x=$x", refSeed.toLong() and 0xFFFFFFFFL, seed)
        }
    }
}

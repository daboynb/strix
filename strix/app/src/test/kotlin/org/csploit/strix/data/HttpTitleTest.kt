package org.csploit.strix.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class HttpTitleTest {

    private fun title(body: String): String? =
        HttpResponses.parseResponse("HTTP/1.1 200 OK\r\nServer: x\r\n\r\n$body", "10.0.0.1", 80, false)?.title

    @Test
    fun numericEntitiesAreDecoded() {
        // Real ZTE H6745 router title
        assertEquals("H6745 V3", title("<title>&#72;&#54;&#55;&#52;&#53;&#32;&#86;&#51;</title>"))
        assertEquals("Hi", title("<title>&#x48;&#X69;</title>"))
    }

    @Test
    fun namedEntitiesAndWhitespaceAreNormalized() {
        assertEquals("Tom & Jerry <admin>", title("<TITLE id=t>\n  Tom &amp; Jerry\r\n &lt;admin&gt; </TITLE>"))
    }

    @Test
    fun unknownOrInvalidReferencesAreKept() {
        assertEquals("a &bogus; b &#0; c &#xD800;", HtmlEntities.decode("a &bogus; b &#0; c &#xD800;"))
        assertEquals("AT&T", HtmlEntities.decode("AT&T"))
    }

    @Test
    fun blankOrMissingTitleIsNull() {
        assertNull(title("<title> &#32; </title>"))
        assertNull(title("<html>no title</html>"))
    }
}

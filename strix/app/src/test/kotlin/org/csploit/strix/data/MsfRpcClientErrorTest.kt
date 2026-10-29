package org.csploit.strix.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.msgpack.core.MessagePack
import java.io.ByteArrayOutputStream

/**
 * msfrpcd reports failures as a non-200 response whose body is a msgpack map
 * {error, error_class, error_message, ...}. The old code threw a generic
 * "HTTP 500" and never decoded it. parseErrorBody must surface the real
 * error_message / error_class.
 */
class MsfRpcClientErrorTest {

    private fun packErrorMap(vararg pairs: Pair<String, Any>): ByteArray {
        val baos = ByteArrayOutputStream()
        MessagePack.newDefaultPacker(baos).use { p ->
            p.packMapHeader(pairs.size)
            for ((k, v) in pairs) {
                p.packString(k)
                when (v) {
                    is Boolean -> p.packBoolean(v)
                    is String -> p.packString(v)
                    else -> p.packString(v.toString())
                }
            }
        }
        return baos.toByteArray()
    }

    @Test
    fun decodesErrorMessageAndClass() {
        val client = MsfRpcClient()
        val body = packErrorMap(
            "error" to true,
            "error_class" to "Msf::RPC::Exception",
            "error_message" to "Invalid User ID or Password",
        )
        val err = client.parseErrorBody(body)
        assertEquals("Invalid User ID or Password", err?.message)
        assertEquals("Msf::RPC::Exception", err?.errorClass)
    }

    @Test
    fun fallsBackToErrorStringWhenNoMessage() {
        val client = MsfRpcClient()
        val body = packErrorMap(
            "error" to true,
            "error_string" to "Database not loaded",
        )
        val err = client.parseErrorBody(body)
        assertEquals("Database not loaded", err?.message)
    }

    @Test
    fun returnsNullForNonErrorBody() {
        val client = MsfRpcClient()
        // A perfectly valid non-error msgpack map (e.g. a truncated success body).
        val body = packErrorMap("version" to "6.4.0")
        assertNull(client.parseErrorBody(body))
    }

    @Test
    fun returnsNullForGarbageBody() {
        val client = MsfRpcClient()
        assertNull(client.parseErrorBody(byteArrayOf(0x00, 0x01, 0x02)))
    }
}

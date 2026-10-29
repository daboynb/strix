package org.csploit.strix.data.bundle

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class SignatureVerifierTest {
    private val keyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val json = """{"format":1,"id":"msf","version":"6.4.125-r1"}""".toByteArray()

    private fun sign(data: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run { initSign(keyPair.private); update(data); sign() }

    @Test fun pinnedKeyParses() {
        val k = SignatureVerifier.pinnedKey
        assertEquals("EC", k.algorithm)
        assertEquals("X.509", k.format)
    }

    @Test fun validSignatureVerifies() {
        assertTrue(SignatureVerifier.verify(json, sign(json), keyPair.public))
    }

    @Test fun pemRoundTrip() {
        val pem = "-----BEGIN PUBLIC KEY-----\n" +
            Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(keyPair.public.encoded) +
            "\n-----END PUBLIC KEY-----\n"
        assertTrue(SignatureVerifier.verify(json, sign(json), SignatureVerifier.parsePublicKey(pem)))
    }

    @Test fun tamperedJsonFails() {
        val sig = sign(json)
        val tampered = String(json).replace("6.4.125-r1", "6.4.125-r9").toByteArray()
        assertFalse(SignatureVerifier.verify(tampered, sig, keyPair.public))
    }

    @Test fun otherKeyAndPinnedKeyFail() {
        val sig = sign(json)
        assertFalse(SignatureVerifier.verify(json, sig)) // pinned key did not sign it
        assertFalse(SignatureVerifier.verify(json, byteArrayOf(1, 2, 3), keyPair.public)) // garbage DER
    }
}

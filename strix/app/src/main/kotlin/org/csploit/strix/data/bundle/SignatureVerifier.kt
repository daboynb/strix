package org.csploit.strix.data.bundle

import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Verifies bundle manifests against the pinned ECDSA P-256 public key.
 * CI signs the exact manifest bytes with `openssl dgst -sha256 -sign`,
 * producing a DER-encoded signature.
 */
object SignatureVerifier {

    /** X.509 SubjectPublicKeyInfo of the bundle signing key (CI holds the private half). */
    const val PINNED_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVRBOqZAJXz0Pc2B2azWaJ81T/9HS
iqnOJccBkehFUS6tq1MZ0KO+qCOP+h0AM667UgIBpLXuO5nB8mWG6arEoA==
-----END PUBLIC KEY-----"""

    val pinnedKey: PublicKey by lazy { parsePublicKey(PINNED_PUBLIC_KEY_PEM) }

    fun parsePublicKey(pem: String): PublicKey {
        val body = pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .filterNot { it.isWhitespace() }
        val der = Base64.getDecoder().decode(body)
        return KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(der))
    }

    /** True only if [signature] (DER) is a valid SHA256withECDSA signature of [data] by [key]. */
    fun verify(data: ByteArray, signature: ByteArray, key: PublicKey = pinnedKey): Boolean =
        try {
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(key)
                update(data)
                verify(signature)
            }
        } catch (_: Exception) {
            // Malformed DER etc. is a verification failure, not a crash.
            false
        }
}

package dev.digitalcredentials.flutter_wallet.openid4vp

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Response encryption, which a verifier either decrypts or rejects with
 * nothing useful to say about why.
 *
 * Two kinds of check: a known-answer test against the worked example in
 * RFC 7518 Appendix C, so the key derivation is verified against something
 * other than itself, and a round trip, so the pieces the compact
 * serialization has to agree on — AAD, IV placement, tag split — are
 * exercised end to end.
 */
class JweTest {

    private val base64Url = Base64.getUrlDecoder()
    private val base64UrlNoPad = Base64.getUrlEncoder().withoutPadding()

    /**
     * RFC 7518 Appendix C, the Concat KDF example for ECDH-ES with A128GCM.
     *
     * Non-empty apu and apv on purpose: they are length-prefixed into the
     * hash, and an implementation that drops either still passes a test that
     * only uses empty ones.
     */
    @Test
    fun `derives the key of the RFC 7518 worked example`() {
        val z = byteArrayOf(
            158.toByte(), 86, 217.toByte(), 29, 129.toByte(), 113, 53, 211.toByte(),
            114, 131.toByte(), 66, 131.toByte(), 191.toByte(), 132.toByte(), 38, 156.toByte(),
            251.toByte(), 49, 110, 163.toByte(), 218.toByte(), 128.toByte(), 106, 72,
            246.toByte(), 218.toByte(), 167.toByte(), 121, 140.toByte(), 254.toByte(),
            144.toByte(), 196.toByte(),
        )

        val derived = concatKdf(
            sharedSecret = z,
            keyBits = 128,
            enc = "A128GCM",
            apu = "Alice".toByteArray(),
            apv = "Bob".toByteArray(),
        )

        assertEquals("VqqN6vgjbSBcIijNcacQGg", base64UrlNoPad.encodeToString(derived))
    }

    /**
     * The thumbprint the verifier recomputes to check the handover.
     *
     * RFC 7638 fixes the serialization: the four required members, no
     * whitespace, lexicographic order. The expected value was computed
     * outside this codebase, from the key the EUDI demo verifier advertises.
     */
    @Test
    fun `thumbprints an EC key as RFC 7638 prescribes`() {
        val key = ResponseEncryptionKey(
            x = "nbGaWZ8PFFB4k0nC_yrrkbeAspaKsKJ4yui32Hjj-QM",
            y = "p6ZZMpL-kx8bl5m3gCexXLImREdxNH8F6TMR2FBOEDw",
            kid = "demo-verifier-response-enc",
        )

        assertEquals(
            "eB8tHOte6H3SHJtRnBy3V_c4Esezz5ndf7cWb6xvcgE",
            base64UrlNoPad.encodeToString(jwkThumbprintSha256(key)),
        )
    }

    /** The kid names the key but is not part of the thumbprint. */
    @Test
    fun `thumbprint ignores everything but the required members`() {
        val withKid = ResponseEncryptionKey(x = X, y = Y, kid = "some-kid")
        val without = ResponseEncryptionKey(x = X, y = Y)

        assertEquals(
            jwkThumbprintSha256(withKid).toList(),
            jwkThumbprintSha256(without).toList(),
        )
    }

    @Test
    fun `round trips a response through A128GCM`() {
        val recipient = generateKeyPair()
        val payload = """{"vp_token":{"employee":["ZXhhbXBsZQ"]}}"""

        val jwe = jweCompact(recipient.encryptionKey(), "A128GCM", payload)

        assertEquals(payload, decrypt(jwe, recipient.private))
    }

    @Test
    fun `round trips a response through A256GCM`() {
        val recipient = generateKeyPair()
        val payload = """{"vp_token":{"employee":["ZXhhbXBsZQ"]}}"""

        val jwe = jweCompact(recipient.encryptionKey(), "A256GCM", payload)

        assertEquals(payload, decrypt(jwe, recipient.private))
    }

    /** Direct Key Agreement wraps no key, so the second segment is empty. */
    @Test
    fun `leaves the encrypted key segment empty`() {
        val jwe = jweCompact(generateKeyPair().encryptionKey(), "A128GCM", "{}")

        val segments = jwe.split(".")
        assertEquals(5, segments.size)
        assertEquals("", segments[1])
    }

    /** A tampered header must fail the tag rather than change how it decrypts. */
    @Test
    fun `binds the protected header into the tag`() {
        val recipient = generateKeyPair()
        val jwe = jweCompact(recipient.encryptionKey(), "A128GCM", "{}")
        val segments = jwe.split(".").toMutableList()
        val header = String(base64Url.decode(segments[0]))
        segments[0] = base64UrlNoPad.encodeToString(
            header.replace("\"A128GCM\"", "\"A256GCM\"").toByteArray()
        )

        assertFailsWith<javax.crypto.AEADBadTagException> {
            decrypt(segments.joinToString("."), recipient.private)
        }
    }

    @Test
    fun `refuses a content encryption it does not implement`() {
        val error = assertFailsWith<IllegalArgumentException> {
            jweCompact(generateKeyPair().encryptionKey(), "A128CBC-HS256", "{}")
        }

        assertTrue(error.message!!.contains("A128GCM"), "names what it does implement")
    }

    @Test
    fun `refuses a curve it does not implement`() {
        val key = generateKeyPair().encryptionKey().copy(crv = "P-384")

        assertFailsWith<IllegalArgumentException> { jweCompact(key, "A128GCM", "{}") }
    }

    // --- a verifier, in miniature -------------------------------------------

    /**
     * Decrypts as a verifier would: read the ephemeral key out of the header,
     * agree, derive, then open the ciphertext with the encoded header as AAD.
     */
    private fun decrypt(jwe: String, privateKey: PrivateKey): String {
        val segments = jwe.split(".")
        val headerEncoded = segments[0]
        val header = String(base64Url.decode(headerEncoded))

        val enc = Regex(""""enc":"([^"]+)"""").find(header)!!.groupValues[1]
        val epkX = Regex(""""x":"([^"]+)"""").findAll(header).last().groupValues[1]
        val epkY = Regex(""""y":"([^"]+)"""").findAll(header).last().groupValues[1]

        val sharedSecret = KeyAgreement.getInstance("ECDH").run {
            init(privateKey)
            doPhase(publicKeyOf(epkX, epkY), true)
            generateSecret()
        }
        val contentKey = concatKdf(sharedSecret, if (enc == "A256GCM") 256 else 128, enc)

        val iv = base64Url.decode(segments[2])
        val sealed = base64Url.decode(segments[3]) + base64Url.decode(segments[4])
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(contentKey, "AES"), GCMParameterSpec(128, iv))
            updateAAD(headerEncoded.toByteArray())
        }
        return String(cipher.doFinal(sealed))
    }

    private fun generateKeyPair(): KeyPair = KeyPairGenerator.getInstance("EC")
        .apply { initialize(ECGenParameterSpec("secp256r1")) }
        .genKeyPair()

    private fun KeyPair.encryptionKey(): ResponseEncryptionKey {
        val point = (public as ECPublicKey).w
        return ResponseEncryptionKey(
            x = base64UrlNoPad.encodeToString(point.affineX.toUnsigned(32)),
            y = base64UrlNoPad.encodeToString(point.affineY.toUnsigned(32)),
            kid = "test-key",
        )
    }

    private fun publicKeyOf(x: String, y: String): ECPublicKey {
        val parameters = AlgorithmParameters.getInstance("EC").apply {
            init(ECGenParameterSpec("secp256r1"))
        }
        val spec = ECPublicKeySpec(
            ECPoint(BigInteger(1, base64Url.decode(x)), BigInteger(1, base64Url.decode(y))),
            parameters.getParameterSpec(ECParameterSpec::class.java),
        )
        return KeyFactory.getInstance("EC").generatePublic(spec) as ECPublicKey
    }

    private fun BigInteger.toUnsigned(width: Int): ByteArray {
        val bytes = toByteArray()
        if (bytes.size == width) return bytes
        val fixed = ByteArray(width)
        if (bytes.size > width) {
            bytes.copyInto(fixed, 0, bytes.size - width, bytes.size)
        } else {
            bytes.copyInto(fixed, width - bytes.size, 0, bytes.size)
        }
        return fixed
    }

    private companion object {
        const val X = "nbGaWZ8PFFB4k0nC_yrrkbeAspaKsKJ4yui32Hjj-QM"
        const val Y = "p6ZZMpL-kx8bl5m3gCexXLImREdxNH8F6TMR2FBOEDw"
    }
}

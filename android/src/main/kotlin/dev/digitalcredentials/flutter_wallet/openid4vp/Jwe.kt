package dev.digitalcredentials.flutter_wallet.openid4vp

import dev.digitalcredentials.flutter_wallet.decodeBase64UrlNoPadding
import dev.digitalcredentials.flutter_wallet.toBase64UrlNoPadding
import dev.digitalcredentials.flutter_wallet.toFixedByteArray
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Response encryption for `response_mode: dc_api.jwt`.
 *
 * The verifier publishes a P-256 key in `client_metadata.jwks`; the wallet
 * derives a content encryption key from it with ECDH-ES in Direct Key
 * Agreement mode (RFC 7518 §4.6) and returns the `vp_token` as a JWE in
 * compact serialization. HAIP 1.0 requires this, so most of the EU ecosystem
 * asks for it and refuses a plain `dc_api` response.
 *
 * Deliberately narrow: ECDH-ES on P-256 with A128GCM or A256GCM, the only
 * combination HAIP allows. Anything else is rejected with the algorithm in
 * the message, because the alternative is a decryption failure at the
 * verifier that names nothing.
 */

/** A verifier's response encryption key, as advertised in `client_metadata.jwks`. */
data class ResponseEncryptionKey(
    val x: String,
    val y: String,
    val kid: String? = null,
    val crv: String = "P-256",
)

/**
 * The RFC 7638 thumbprint of [key], which the handover binds the response to.
 *
 * The JSON is built by hand: the thumbprint is only reproducible if the
 * members are the required four, in lexicographic order, with no whitespace,
 * and no JSON object type promises an iteration order. CMWallet builds this
 * with `JSONObject`, which is a `HashMap` underneath — it happens to agree
 * for these four keys, but not by contract.
 */
fun jwkThumbprintSha256(key: ResponseEncryptionKey): ByteArray {
    val canonical = """{"crv":"${key.crv}","kty":"EC","x":"${key.x}","y":"${key.y}"}"""
    return MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray(Charsets.UTF_8))
}

/**
 * Encrypts [plaintext] to [key], returning a JWE in compact serialization.
 *
 * [enc] is the content encryption algorithm the verifier asked for, either
 * `A128GCM` or `A256GCM`.
 */
fun jweCompact(key: ResponseEncryptionKey, enc: String, plaintext: String): String {
    val keyBits = when (enc) {
        "A128GCM" -> 128
        "A256GCM" -> 256
        else -> throw IllegalArgumentException(
            "unsupported content encryption \"$enc\"; this wallet implements A128GCM and A256GCM"
        )
    }
    require(key.crv == "P-256") {
        "unsupported curve \"${key.crv}\"; ECDH-ES on P-256 is the only key agreement implemented"
    }

    val recipient = toEcPublicKey(key.x, key.y)
    val ephemeral = KeyPairGenerator.getInstance("EC")
        .apply { initialize(ECGenParameterSpec("secp256r1")) }
        .genKeyPair()

    // apu and apv stay empty, as CMWallet sends them and verifiers accept.
    // They are inputs to the KDF, so a recipient derives the same key from
    // the header it receives either way.
    val header = buildString {
        append("""{"alg":"ECDH-ES","enc":"$enc","apu":"","apv":"",""")
        if (key.kid != null) append(""""kid":${jsonString(key.kid)},""")
        val point = (ephemeral.public as ECPublicKey).w
        append(""""epk":{"crv":"P-256","kty":"EC"""")
        append(""","x":"${point.affineX.toFixedByteArray(32).toBase64UrlNoPadding()}"""")
        append(""","y":"${point.affineY.toFixedByteArray(32).toBase64UrlNoPadding()}"}}""")
    }
    val headerEncoded = header.toByteArray(Charsets.UTF_8).toBase64UrlNoPadding()

    val sharedSecret = KeyAgreement.getInstance("ECDH").run {
        init(ephemeral.private)
        doPhase(recipient, true)
        generateSecret()
    }
    val contentKey = concatKdf(sharedSecret, keyBits, enc)

    val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
    val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
        init(Cipher.ENCRYPT_MODE, SecretKeySpec(contentKey, "AES"), GCMParameterSpec(128, iv))
        // The protected header authenticates the algorithms and the ephemeral
        // key, so a tampered header fails the tag rather than silently
        // changing how the response is read.
        updateAAD(headerEncoded.toByteArray(Charsets.US_ASCII))
    }
    val sealed = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
    val ciphertext = sealed.copyOfRange(0, sealed.size - 16)
    val tag = sealed.copyOfRange(sealed.size - 16, sealed.size)

    // The encrypted key is empty: Direct Key Agreement uses the derived key
    // as the content encryption key rather than wrapping one.
    return "$headerEncoded..${iv.toBase64UrlNoPadding()}." +
        "${ciphertext.toBase64UrlNoPadding()}.${tag.toBase64UrlNoPadding()}"
}

/**
 * The Concat KDF of NIST SP 800-56A §5.8.1, as RFC 7518 §4.6.2 parameterises
 * it for Direct Key Agreement: `AlgorithmID` is the `enc` value, `PartyUInfo`
 * and `PartyVInfo` are empty, and `SuppPubInfo` is the key length in bits.
 *
 * CMWallet gets this from jose4j. Reimplemented here because the dependency
 * went when the plugin was trimmed, and it is one hash for both key sizes.
 */
internal fun concatKdf(
    sharedSecret: ByteArray,
    keyBits: Int,
    enc: String,
    apu: ByteArray = ByteArray(0),
    apv: ByteArray = ByteArray(0),
): ByteArray {
    val algorithmId = lengthPrefixed(enc.toByteArray(Charsets.US_ASCII))
    val partyUInfo = lengthPrefixed(apu)
    val partyVInfo = lengthPrefixed(apv)
    val suppPubInfo = intBytes(keyBits)

    val digest = MessageDigest.getInstance("SHA-256")
    val bytes = keyBits / 8
    val derived = ByteArray(bytes)
    var written = 0
    var counter = 1
    while (written < bytes) {
        digest.reset()
        digest.update(intBytes(counter))
        digest.update(sharedSecret)
        digest.update(algorithmId)
        digest.update(partyUInfo)
        digest.update(partyVInfo)
        digest.update(suppPubInfo)
        val block = digest.digest()
        val take = minOf(block.size, bytes - written)
        block.copyInto(derived, written, 0, take)
        written += take
        counter++
    }
    return derived
}

private fun lengthPrefixed(data: ByteArray): ByteArray = intBytes(data.size) + data

private fun intBytes(value: Int): ByteArray =
    ByteBuffer.allocate(4).putInt(value).array()

private fun toEcPublicKey(x: String, y: String): ECPublicKey {
    val parameters = AlgorithmParameters.getInstance("EC").apply {
        init(ECGenParameterSpec("secp256r1"))
    }
    val spec = ECPublicKeySpec(
        ECPoint(
            BigInteger(1, x.decodeBase64UrlNoPadding()),
            BigInteger(1, y.decodeBase64UrlNoPadding()),
        ),
        parameters.getParameterSpec(ECParameterSpec::class.java),
    )
    return KeyFactory.getInstance("EC").generatePublic(spec) as ECPublicKey
}

/** Quotes a string for the hand-built JWE header. */
private fun jsonString(value: String): String = buildString {
    append('"')
    for (c in value) {
        when {
            c == '"' -> append("\\\"")
            c == '\\' -> append("\\\\")
            c < ' ' -> append("\\u%04x".format(c.code))
            else -> append(c)
        }
    }
    append('"')
}

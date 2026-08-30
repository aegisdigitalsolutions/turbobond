package com.aegisdigital.turbobond.core

import org.bouncycastle.crypto.digests.Blake2bDigest
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter

const val KEY_LEN = 32
const val NONCE_LEN = 12
const val TAG_LEN = 16

private const val KDF_LABEL = "turbobond-tunnel-v1"

/**
 * Turn the hex pre-shared key into the 32-byte AEAD key.
 *
 * Must stay identical to `turbobond.util.crypto.derive_key`, including the
 * personalisation being the label truncated to 16 bytes: the two ends derive
 * independently and never exchange the result, so a mismatch shows up only as
 * datagrams being silently dropped by the concentrator.
 */
fun deriveKey(pskHex: String): ByteArray {
    val psk = pskHex.trim().hexToBytesOrNull()
        ?: throw BondException("the pre-shared key must be hex encoded")
    if (psk.size < 16) {
        throw BondException("the pre-shared key must be at least 16 bytes (32 hex characters)")
    }
    val personalisation = KDF_LABEL.toByteArray(Charsets.UTF_8).copyOf(16)
    // Blake2bDigest(key, digestSize, salt, personalisation); no key, no salt.
    val digest = Blake2bDigest(null, KEY_LEN, null, personalisation)
    digest.update(psk, 0, psk.size)
    val out = ByteArray(KEY_LEN)
    digest.doFinal(out, 0)
    return out
}

class BondException(message: String) : Exception(message)

private fun String.hexToBytesOrNull(): ByteArray? {
    if (length % 2 != 0) return null
    val out = ByteArray(length / 2)
    for (i in out.indices) {
        val high = Character.digit(this[i * 2], 16)
        val low = Character.digit(this[i * 2 + 1], 16)
        if (high < 0 || low < 0) return null
        out[i] = ((high shl 4) or low).toByte()
    }
    return out
}

/** Seals and opens tunnel datagrams with ChaCha20-Poly1305. */
class Sealer(private val key: ByteArray) {

    init {
        if (key.size != KEY_LEN) throw BondException("tunnel key must be $KEY_LEN bytes, got ${key.size}")
    }

    companion object {
        fun fromPsk(pskHex: String): Sealer = Sealer(deriveKey(pskHex))

        /** 12-byte nonce: 4-byte link id, then 8-byte counter, both big endian. */
        fun nonce(linkId: Int, counter: Long): ByteArray {
            val out = ByteArray(NONCE_LEN)
            for (i in 0 until 4) out[i] = (linkId ushr (8 * (3 - i))).toByte()
            for (i in 0 until 8) out[4 + i] = (counter ushr (8 * (7 - i))).toByte()
            return out
        }
    }

    private fun cipher(): ChaCha20Poly1305 = ChaCha20Poly1305()

    fun seal(plaintext: ByteArray, linkId: Int, counter: Long, aad: ByteArray): ByteArray {
        val engine = cipher()
        engine.init(true, AEADParameters(KeyParameter(key), TAG_LEN * 8, nonce(linkId, counter), aad))
        val out = ByteArray(engine.getOutputSize(plaintext.size))
        val written = engine.processBytes(plaintext, 0, plaintext.size, out, 0)
        engine.doFinal(out, written)
        return out
    }

    /** Returns the plaintext, or null when authentication fails. */
    fun open(ciphertext: ByteArray, linkId: Int, counter: Long, aad: ByteArray): ByteArray? {
        return try {
            val engine = cipher()
            engine.init(false, AEADParameters(KeyParameter(key), TAG_LEN * 8, nonce(linkId, counter), aad))
            val out = ByteArray(engine.getOutputSize(ciphertext.size))
            val written = engine.processBytes(ciphertext, 0, ciphertext.size, out, 0)
            val total = written + engine.doFinal(out, written)
            if (total == out.size) out else out.copyOf(total)
        } catch (_: Exception) {
            null
        }
    }
}

package com.aegisdigital.turbobond.core

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull

private const val PSK = "abababababababababababababababababababababababababababababababab"

private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

private fun String.unhex(): ByteArray =
    chunked(2).map { it.toInt(16).toByte() }.toByteArray()

/**
 * Vectors produced by the Python implementation. Both ends derive the key and
 * frame packets independently and never compare notes, so a divergence would
 * surface only as the concentrator silently dropping everything. Pinning the
 * exact bytes is what makes that failure impossible to ship.
 */
class InteropVectorTest {

    @Test
    fun `key derivation matches python`() {
        assertEquals(
            "bc5ea11e520900e5de88d810bc5a211fed1d4efa226c0d453c8f9e66b87c0bd7",
            deriveKey(PSK).hex(),
        )
    }

    @Test
    fun `data frame is byte identical to python`() {
        val frame = Protocol.encode(
            Sealer.fromPsk(PSK),
            FrameType.DATA,
            sessionId = 0x11223344,
            linkId = 7,
            counter = 42,
            seq = 99,
            payload = "hello turbobond".toByteArray(),
        )
        assertEquals(
            "544201011122334400000007000000000000002ac782040d54c8af32292d3a" +
                "91d8c6c147fd15d3d3f034c6d2e6a009795b97081b9474d1b735357b",
            frame.hex(),
        )
    }

    @Test
    fun `handshake frame is byte identical to python`() {
        val frame = Protocol.encode(
            Sealer.fromPsk(PSK), FrameType.HANDSHAKE, sessionId = 0xC0FFEE, linkId = 1, counter = 1,
        )
        assertEquals(
            "5442010300c0ffee0000000100000000000000012adb0d909b50c90c15eaaf71fd5cd435b78cd1ec06766411",
            frame.hex(),
        )
    }

    @Test
    fun `keepalive frame is byte identical to python`() {
        val frame = Protocol.encode(
            Sealer.fromPsk(PSK), FrameType.KEEPALIVE, sessionId = 1, linkId = 2, counter = 3, seq = 4,
        )
        assertEquals(
            "54420102000000010000000200000000000000033f054d20847c7968bb5b0137bdc0b42abe86cd3a5ef78f6a",
            frame.hex(),
        )
    }

    @Test
    fun `frames built by python decode here`() {
        val python = ("544201011122334400000007000000000000002ac782040d54c8af32292d3a" +
            "91d8c6c147fd15d3d3f034c6d2e6a009795b97081b9474d1b735357b").unhex()

        val frame = assertNotNull(Protocol.decode(Sealer.fromPsk(PSK), python))

        assertEquals(FrameType.DATA, frame.type)
        assertEquals(0x11223344, frame.sessionId)
        assertEquals(7, frame.linkId)
        assertEquals(42L, frame.counter)
        assertEquals(99L, frame.seq)
        assertContentEquals("hello turbobond".toByteArray(), frame.payload)
    }
}

class RoundTripTest {

    @Test
    fun `encode then decode returns what went in`() {
        val sealer = Sealer.fromPsk(PSK)
        val payload = ByteArray(1200) { (it % 251).toByte() }

        val frame = assertNotNull(
            Protocol.decode(
                sealer,
                Protocol.encode(sealer, FrameType.DATA, 9, 3, 77, seq = 5, payload = payload),
            ),
        )

        assertContentEquals(payload, frame.payload)
        assertEquals(5L, frame.seq)
    }

    @Test
    fun `a different key does not authenticate`() {
        val datagram = Protocol.encode(Sealer.fromPsk(PSK), FrameType.DATA, 1, 1, 1, payload = "x".toByteArray())
        val other = Sealer.fromPsk("cd".repeat(32))

        assertNull(Protocol.decode(other, datagram))
    }

    @Test
    fun `a tampered header does not authenticate`() {
        val datagram = Protocol.encode(Sealer.fromPsk(PSK), FrameType.DATA, 1, 1, 1, payload = "x".toByteArray())
        datagram[8] = (datagram[8] + 1).toByte() // link id, authenticated as AAD

        assertNull(Protocol.decode(Sealer.fromPsk(PSK), datagram))
    }

    @Test
    fun `foreign datagrams are ignored rather than throwing`() {
        val sealer = Sealer.fromPsk(PSK)
        assertNull(Protocol.decode(sealer, ByteArray(4)))
        assertNull(Protocol.decode(sealer, "not a turbobond datagram at all!!".toByteArray()))
    }

    @Test
    fun `oversized payloads are refused`() {
        assertFailsWith<BondException> {
            Protocol.encode(Sealer.fromPsk(PSK), FrameType.DATA, 1, 1, 1, payload = ByteArray(2000))
        }
    }
}

class KeyDerivationTest {

    @Test
    fun `rejects a key that is not hex`() {
        assertFailsWith<BondException> { deriveKey("nonsense!!") }
    }

    @Test
    fun `rejects a key that is too short`() {
        assertFailsWith<BondException> { deriveKey("abcd") }
    }

    @Test
    fun `nonce layout is link id then counter`() {
        val nonce = Sealer.nonce(0x01020304, 0x0A0B0C0D0E0F1011L)
        assertEquals("010203040a0b0c0d0e0f1011", nonce.hex())
    }
}

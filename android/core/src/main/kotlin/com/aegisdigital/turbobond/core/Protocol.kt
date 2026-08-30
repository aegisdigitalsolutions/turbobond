package com.aegisdigital.turbobond.core

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Wire format for the bonding tunnel, matching `turbobond/bond/protocol.py`.
 *
 *     magic(2) | version(1) | type(1) | session id(4) | link id(4) | counter(8)
 *     followed by the AEAD-sealed payload
 *
 * The header is authenticated as additional data, so a middlebox cannot rewrite
 * the link or session id without the far end noticing. Inside the ciphertext a
 * DATA frame carries an 8-byte global sequence number then the original IP
 * packet, which is what the receiver's reorder buffer keys on.
 */
object Protocol {
    val MAGIC = byteArrayOf('T'.code.toByte(), 'B'.code.toByte())
    const val VERSION: Byte = 1
    const val HEADER_LEN = 20
    const val SEQ_LEN = 8
    const val MAX_PAYLOAD = 1600
    const val MAX_DATAGRAM = HEADER_LEN + SEQ_LEN + MAX_PAYLOAD + TAG_LEN

    fun packHeader(type: FrameType, sessionId: Int, linkId: Int, counter: Long): ByteArray =
        ByteBuffer.allocate(HEADER_LEN).order(ByteOrder.BIG_ENDIAN).apply {
            put(MAGIC)
            put(VERSION)
            put(type.value.toByte())
            putInt(sessionId)
            putInt(linkId)
            putLong(counter)
        }.array()

    fun encode(
        sealer: Sealer,
        type: FrameType,
        sessionId: Int,
        linkId: Int,
        counter: Long,
        seq: Long = 0,
        payload: ByteArray = ByteArray(0),
    ): ByteArray {
        if (payload.size > MAX_PAYLOAD) {
            throw BondException("payload of ${payload.size} bytes exceeds the $MAX_PAYLOAD byte limit")
        }
        val header = packHeader(type, sessionId, linkId, counter)
        val plaintext = ByteBuffer.allocate(SEQ_LEN + payload.size)
            .order(ByteOrder.BIG_ENDIAN)
            .putLong(seq)
            .put(payload)
            .array()
        return header + sealer.seal(plaintext, linkId, counter, header)
    }

    /** Returns the decoded frame, or null when the datagram is not ours or fails to authenticate. */
    fun decode(sealer: Sealer, data: ByteArray): Frame? {
        if (data.size < HEADER_LEN) return null
        val buf = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
        val magic = ByteArray(2).also { buf.get(it) }
        if (!magic.contentEquals(MAGIC)) return null
        if (buf.get() != VERSION) return null
        val type = FrameType.fromValue(buf.get().toInt() and 0xFF) ?: return null
        val sessionId = buf.int
        val linkId = buf.int
        val counter = buf.long

        val header = data.copyOfRange(0, HEADER_LEN)
        val ciphertext = data.copyOfRange(HEADER_LEN, data.size)
        val plaintext = sealer.open(ciphertext, linkId, counter, header) ?: return null
        if (plaintext.size < SEQ_LEN) return null

        return Frame(
            type = type,
            sessionId = sessionId,
            linkId = linkId,
            counter = counter,
            seq = ByteBuffer.wrap(plaintext, 0, SEQ_LEN).order(ByteOrder.BIG_ENDIAN).long,
            payload = plaintext.copyOfRange(SEQ_LEN, plaintext.size),
        )
    }
}

enum class FrameType(val value: Int) {
    DATA(1),
    KEEPALIVE(2),
    HANDSHAKE(3),
    HANDSHAKE_ACK(4),
    LINK_STATS(5),
    CLOSE(6);

    companion object {
        private val byValue = entries.associateBy { it.value }
        fun fromValue(value: Int): FrameType? = byValue[value]
    }
}

data class Frame(
    val type: FrameType,
    val sessionId: Int,
    val linkId: Int,
    val counter: Long,
    val seq: Long,
    val payload: ByteArray,
) {
    val isData: Boolean get() = type == FrameType.DATA

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Frame) return false
        return type == other.type && sessionId == other.sessionId && linkId == other.linkId &&
            counter == other.counter && seq == other.seq && payload.contentEquals(other.payload)
    }

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + sessionId
        result = 31 * result + linkId
        result = 31 * result + counter.hashCode()
        result = 31 * result + seq.hashCode()
        result = 31 * result + payload.contentHashCode()
        return result
    }
}

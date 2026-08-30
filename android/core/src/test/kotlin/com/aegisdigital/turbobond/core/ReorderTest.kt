package com.aegisdigital.turbobond.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

private fun packet(n: Int) = byteArrayOf(n.toByte())

private fun List<ByteArray>.ids() = map { it[0].toInt() }

class ReorderTest {

    @Test
    fun `packets already in order pass straight through`() {
        val buffer = ReorderBuffer()
        assertEquals(listOf(0), buffer.push(0, packet(0), now = 0).ids())
        assertEquals(listOf(1), buffer.push(1, packet(1), now = 1).ids())
        assertEquals(listOf(2), buffer.push(2, packet(2), now = 2).ids())
    }

    @Test
    fun `a packet that overtakes another is held until the gap fills`() {
        val buffer = ReorderBuffer(timeoutMs = 90)

        assertEquals(listOf(0), buffer.push(0, packet(0), now = 0).ids())
        // Sequence 2 arrives over the fast link before 1 arrives over the slow one.
        assertTrue(buffer.push(2, packet(2), now = 10).isEmpty())
        assertEquals(listOf(1, 2), buffer.push(1, packet(1), now = 20).ids())
    }

    @Test
    fun `a lost packet does not stall the tunnel forever`() {
        val buffer = ReorderBuffer(timeoutMs = 90)

        buffer.push(0, packet(0), now = 0)
        assertTrue(buffer.push(2, packet(2), now = 10).isEmpty())

        // Sequence 1 never arrives; once the wait expires, 2 is delivered anyway.
        assertEquals(listOf(2), buffer.tick(now = 200).ids())
    }

    @Test
    fun `the ticker waits out the timeout before giving up on a gap`() {
        val buffer = ReorderBuffer(timeoutMs = 50)
        buffer.push(0, packet(0), now = 0)
        buffer.push(2, packet(2), now = 0)

        // Still inside the window: the missing packet may yet arrive.
        assertTrue(buffer.tick(now = 10).isEmpty())
        assertEquals(listOf(2), buffer.tick(now = 100).ids())
    }

    @Test
    fun `duplicates from a second link are dropped`() {
        val buffer = ReorderBuffer()
        buffer.push(0, packet(0), now = 0)
        buffer.push(1, packet(1), now = 1)

        // Critical packets are deliberately sent over every link, so the copies
        // arrive too and must not be delivered twice.
        assertTrue(buffer.push(1, packet(1), now = 2).isEmpty())
        assertTrue(buffer.push(0, packet(0), now = 3).isEmpty())
    }

    @Test
    fun `a full buffer gives up on the gap rather than growing`() {
        val buffer = ReorderBuffer(timeoutMs = 10_000, capacity = 4)
        buffer.push(0, packet(0), now = 0)

        buffer.push(2, packet(2), now = 0)
        buffer.push(3, packet(3), now = 0)
        buffer.push(4, packet(4), now = 0)
        val released = buffer.push(5, packet(5), now = 0)

        assertEquals(listOf(2, 3, 4, 5), released.ids())
        assertEquals(0, buffer.size)
    }

    @Test
    fun `starting mid-stream does not wait for sequence zero`() {
        val buffer = ReorderBuffer()
        assertEquals(listOf(9), buffer.push(1000, packet(9), now = 0).ids())
    }

    @Test
    fun `a long burst arrives complete and in order however it is shuffled`() {
        val buffer = ReorderBuffer(timeoutMs = 90)
        val delivered = mutableListOf<Int>()

        // Two links: even sequences arrive late, odd ones early.
        val arrivals = (0 until 40).sortedBy { if (it % 2 == 0) it + 1 else it }
        for ((tick, seq) in arrivals.withIndex()) {
            delivered += buffer.push(seq.toLong(), packet(seq), now = tick.toLong()).ids()
        }
        delivered += buffer.tick(now = 10_000).ids()

        assertEquals((0 until 40).toList(), delivered)
    }
}

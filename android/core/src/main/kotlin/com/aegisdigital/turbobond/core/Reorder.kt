package com.aegisdigital.turbobond.core

import java.util.TreeMap

/**
 * Puts packets back in order after they arrive across several uplinks.
 *
 * Links have different latencies, so a packet sent second over a fast link
 * routinely arrives before one sent first over a slow one. Handing those to the
 * IP stack as they land looks like heavy reordering and collapses TCP
 * throughput, so a gap is held briefly in case the missing packet is still in
 * flight, then given up on so a genuinely lost packet cannot stall the tunnel.
 */
class ReorderBuffer(
    private val timeoutMs: Long = 90,
    private val capacity: Int = 2048,
) {
    private val pending = TreeMap<Long, ByteArray>()
    private var nextSeq = -1L
    private var deadline = 0L

    val size: Int get() = pending.size

    /**
     * Accept a packet and return whatever is now deliverable, in order.
     *
     * [now] is passed in rather than read from the clock so the behaviour is
     * testable without sleeping.
     */
    fun push(seq: Long, packet: ByteArray, now: Long = System.currentTimeMillis()): List<ByteArray> {
        if (nextSeq < 0) {
            nextSeq = seq
            deadline = now + timeoutMs
        }
        // Anything already delivered is a duplicate from another link.
        if (seq < nextSeq) return emptyList()

        pending[seq] = packet
        if (pending.size == 1) deadline = now + timeoutMs

        val ready = drainContiguous()
        return when {
            ready.isNotEmpty() -> {
                deadline = now + timeoutMs
                ready
            }
            pending.size >= capacity -> flushOldest(now)
            now >= deadline -> flushOldest(now)
            else -> emptyList()
        }
    }

    /**
     * Release anything whose wait has expired.
     *
     * Called on a timer as well as on arrival, because a gap at the head with
     * no further packets behind it would otherwise sit there indefinitely.
     */
    fun tick(now: Long = System.currentTimeMillis()): List<ByteArray> {
        if (pending.isEmpty() || now < deadline) return emptyList()
        return flushOldest(now)
    }

    fun reset() {
        pending.clear()
        nextSeq = -1
        deadline = 0
    }

    private fun drainContiguous(): List<ByteArray> {
        val out = mutableListOf<ByteArray>()
        while (true) {
            val packet = pending.remove(nextSeq) ?: break
            out.add(packet)
            nextSeq++
        }
        return out
    }

    /** Give up on the missing packet, skip to the oldest we do have, and carry on. */
    private fun flushOldest(now: Long): List<ByteArray> {
        val first = pending.firstKey() ?: return emptyList()
        nextSeq = first
        val out = drainContiguous()
        deadline = now + timeoutMs
        return out
    }
}

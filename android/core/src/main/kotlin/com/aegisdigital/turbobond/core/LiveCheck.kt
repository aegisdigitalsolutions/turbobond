package com.aegisdigital.turbobond.core

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import kotlin.system.exitProcess

/**
 * Dials a real concentrator and reports whether it answers.
 *
 * The Android app cannot be exercised on a build machine, but the half that
 * decides whether a bond can form at all -- key derivation, framing, and the
 * handshake -- is plain JVM code. This runs that half against a live server so
 * it is verified before it is ever put on a phone.
 *
 *     gradle :core:run --args="<host> <port> <psk-hex> [uplinks]"
 */
object LiveCheck {

    @JvmStatic
    fun main(args: Array<String>) {
        if (args.size < 3) {
            System.err.println("usage: LiveCheck <host> <port> <psk-hex> [uplinks]")
            exitProcess(2)
        }
        val host = InetAddress.getByName(args[0])
        val port = args[1].toInt()
        val sealer = try {
            Sealer.fromPsk(args[2])
        } catch (exc: BondException) {
            System.err.println("error: ${exc.message}")
            exitProcess(2)
        }
        val uplinks = if (args.size > 3) args[3].toInt() else 2
        val sessionId = 0x5A5A0000 or (System.nanoTime().toInt() and 0xFFFF)

        println("Dialling $host:$port with $uplinks simulated uplinks")
        var paired = 0

        for (linkId in 1..uplinks) {
            DatagramSocket().use { socket ->
                socket.soTimeout = 3000
                val handshake = Protocol.encode(
                    sealer, FrameType.HANDSHAKE, sessionId, linkId, counter = 1,
                )
                socket.send(DatagramPacket(handshake, handshake.size, host, port))

                val buffer = ByteArray(Protocol.MAX_DATAGRAM)
                val reply = DatagramPacket(buffer, buffer.size)
                try {
                    socket.receive(reply)
                } catch (_: SocketTimeoutException) {
                    println("  uplink $linkId: no reply (wrong key, or the port is closed)")
                    return@use
                }

                val frame = Protocol.decode(sealer, buffer.copyOf(reply.length))
                if (frame == null) {
                    println("  uplink $linkId: reply did not authenticate")
                    return@use
                }
                println("  uplink $linkId: ${frame.type} from the concentrator")
                paired++

                // A DATA frame carrying a real IPv4 packet, as the tunnel would.
                val packet = Protocol.encode(
                    sealer, FrameType.DATA, sessionId, linkId,
                    counter = 2, seq = linkId.toLong(), payload = ipv4Probe(),
                )
                socket.send(DatagramPacket(packet, packet.size, host, port))
            }
        }

        println()
        if (paired == uplinks) {
            println("PASS: all $uplinks uplinks paired with the concentrator.")
            exitProcess(0)
        }
        println("FAIL: $paired of $uplinks uplinks paired.")
        exitProcess(1)
    }

    /** A minimal well-formed IPv4/UDP datagram for the tunnel to carry. */
    private fun ipv4Probe(): ByteArray {
        val payload = "turbobond".toByteArray()
        val udp = ByteArray(8 + payload.size)
        writeShort(udp, 0, 40000)
        writeShort(udp, 2, 53)
        writeShort(udp, 4, udp.size)
        payload.copyInto(udp, 8)

        val ip = ByteArray(20 + udp.size)
        ip[0] = 0x45
        writeShort(ip, 2, ip.size)
        writeShort(ip, 4, 1)
        ip[8] = 64
        ip[9] = 17
        byteArrayOf(10, 77, 0, 2).copyInto(ip, 12)
        byteArrayOf(1, 1, 1, 1).copyInto(ip, 16)
        udp.copyInto(ip, 20)
        return ip
    }

    private fun writeShort(buf: ByteArray, offset: Int, value: Int) {
        buf[offset] = (value ushr 8).toByte()
        buf[offset + 1] = value.toByte()
    }
}

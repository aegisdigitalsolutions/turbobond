package com.aegisdigital.turbobond.core

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * A SOCKS5 proxy, so devices that cannot run the bonding client can still use
 * the bond.
 *
 * On Android this is the way around a hard platform limit. Traffic forwarded
 * from a hotspot client is handled in the kernel and never enters the VPN
 * interface an app is given, so a tablet on the phone's hotspot bypasses the
 * tunnel entirely. Traffic that *originates* from an app on the phone does go
 * through it. A proxy turns the first case into the second: the tablet's
 * connection terminates here, and the onward connection this makes is the
 * phone's own, so it is bonded like everything else.
 *
 * Only CONNECT is implemented. That covers TCP, which is what a proxy client
 * such as Surge sends; UDP would need ASSOCIATE and a separate relay.
 */
class SocksProxy(
    private val port: Int = DEFAULT_PORT,
    private val bindAddress: String = "0.0.0.0",
    private val connectTimeoutMs: Int = 10_000,
    /** Android supplies plain sockets here; they must not be protected from the VPN. */
    private val socketFactory: () -> Socket = { Socket() },
) {
    private val running = AtomicBoolean(false)
    private val active = AtomicInteger(0)
    private var server: ServerSocket? = null
    private val pool = Executors.newCachedThreadPool { task ->
        Thread(task, "socks-worker").apply { isDaemon = true }
    }

    val isRunning: Boolean get() = running.get()
    val activeConnections: Int get() = active.get()
    val boundPort: Int get() = server?.localPort ?: port

    fun start() {
        if (running.getAndSet(true)) return
        val socket = ServerSocket()
        socket.reuseAddress = true
        socket.bind(InetSocketAddress(InetAddress.getByName(bindAddress), port))
        server = socket

        pool.execute {
            while (running.get()) {
                val client = try {
                    socket.accept()
                } catch (_: IOException) {
                    break
                }
                pool.execute { serve(client) }
            }
        }
    }

    fun stop() {
        if (!running.getAndSet(false)) return
        runCatching { server?.close() }
        server = null
        pool.shutdownNow()
    }

    private fun serve(client: Socket) {
        active.incrementAndGet()
        var upstream: Socket? = null
        try {
            client.tcpNoDelay = true
            val input = client.getInputStream()
            val output = client.getOutputStream()

            if (!greet(input, output)) return
            val target = readRequest(input, output) ?: return

            upstream = socketFactory().apply {
                tcpNoDelay = true
                connect(InetSocketAddress(target.host, target.port), connectTimeoutMs)
            }
            output.write(reply(REPLY_SUCCESS))
            output.flush()

            // One direction on this thread, the other on the pool.
            val toUpstream = pool.submit { relay(input, upstream.getOutputStream()) }
            relay(upstream.getInputStream(), output)
            toUpstream.cancel(true)
        } catch (_: Exception) {
            runCatching { client.getOutputStream().write(reply(REPLY_HOST_UNREACHABLE)) }
        } finally {
            runCatching { upstream?.close() }
            runCatching { client.close() }
            active.decrementAndGet()
        }
    }

    /** Method negotiation. Only "no authentication" is offered. */
    private fun greet(input: InputStream, output: OutputStream): Boolean {
        if (input.readOrNull() != VERSION) return false
        val methodCount = input.readOrNull() ?: return false
        val methods = ByteArray(methodCount)
        if (!input.readFully(methods)) return false

        if (!methods.contains(METHOD_NO_AUTH.toByte())) {
            output.write(byteArrayOf(VERSION.toByte(), METHOD_NONE_ACCEPTABLE.toByte()))
            output.flush()
            return false
        }
        output.write(byteArrayOf(VERSION.toByte(), METHOD_NO_AUTH.toByte()))
        output.flush()
        return true
    }

    private fun readRequest(input: InputStream, output: OutputStream): Target? {
        if (input.readOrNull() != VERSION) return null
        val command = input.readOrNull() ?: return null
        input.readOrNull() // reserved
        val addressType = input.readOrNull() ?: return null

        val host = when (addressType) {
            ATYP_IPV4 -> ByteArray(4).also { if (!input.readFully(it)) return null }
                .joinToString(".") { (it.toInt() and 0xFF).toString() }

            ATYP_DOMAIN -> {
                val length = input.readOrNull() ?: return null
                val name = ByteArray(length)
                if (!input.readFully(name)) return null
                String(name, Charsets.US_ASCII)
            }

            ATYP_IPV6 -> ByteArray(16).also { if (!input.readFully(it)) return null }
                .let { InetAddress.getByAddress(it).hostAddress ?: return null }

            else -> {
                output.write(reply(REPLY_ADDRESS_UNSUPPORTED))
                output.flush()
                return null
            }
        }

        val portBytes = ByteArray(2)
        if (!input.readFully(portBytes)) return null
        val port = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)

        if (command != CMD_CONNECT) {
            output.write(reply(REPLY_COMMAND_UNSUPPORTED))
            output.flush()
            return null
        }
        return Target(host, port)
    }

    /**
     * The bound address in the reply is left as zeroes.
     *
     * Clients use it only for BIND and UDP ASSOCIATE, neither of which is
     * offered here, and reporting the phone's own address would leak it to
     * every device on the hotspot for no benefit.
     */
    private fun reply(code: Int): ByteArray = byteArrayOf(
        VERSION.toByte(), code.toByte(), 0, ATYP_IPV4.toByte(), 0, 0, 0, 0, 0, 0,
    )

    private fun relay(from: InputStream, to: OutputStream) {
        val buffer = ByteArray(16 * 1024)
        try {
            while (true) {
                val read = from.read(buffer)
                if (read < 0) break
                to.write(buffer, 0, read)
                to.flush()
            }
        } catch (_: IOException) {
            // Either end closing is the normal way a connection ends.
        }
    }

    private data class Target(val host: String, val port: Int)

    companion object {
        const val DEFAULT_PORT = 1080
        private const val VERSION = 5
        private const val METHOD_NO_AUTH = 0
        private const val METHOD_NONE_ACCEPTABLE = 0xFF
        private const val CMD_CONNECT = 1
        private const val ATYP_IPV4 = 1
        private const val ATYP_DOMAIN = 3
        private const val ATYP_IPV6 = 4
        private const val REPLY_SUCCESS = 0
        private const val REPLY_HOST_UNREACHABLE = 4
        private const val REPLY_COMMAND_UNSUPPORTED = 7
        private const val REPLY_ADDRESS_UNSUPPORTED = 8
    }
}

private fun InputStream.readOrNull(): Int? = read().takeIf { it >= 0 }

private fun InputStream.readFully(into: ByteArray): Boolean {
    var offset = 0
    while (offset < into.size) {
        val read = read(into, offset, into.size - offset)
        if (read < 0) return false
        offset += read
    }
    return true
}

package com.aegisdigital.turbobond.core

import java.io.DataInputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import kotlin.concurrent.thread
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The proxy is what lets a device that cannot run the client use the bond, so
 * it is exercised against a real server over real sockets rather than mocked.
 */
class SocksProxyTest {

    private lateinit var proxy: SocksProxy
    private lateinit var echo: ServerSocket
    private var echoPort = 0

    @BeforeTest
    fun setUp() {
        echo = ServerSocket(0)
        echoPort = echo.localPort
        thread(isDaemon = true) {
            while (!echo.isClosed) {
                val client = try { echo.accept() } catch (_: Exception) { break }
                thread(isDaemon = true) {
                    runCatching {
                        client.use {
                            val input = it.getInputStream()
                            val output = it.getOutputStream()
                            val buffer = ByteArray(4096)
                            while (true) {
                                val read = input.read(buffer)
                                if (read < 0) break
                                output.write(buffer, 0, read)
                                output.flush()
                            }
                        }
                    }
                }
            }
        }

        proxy = SocksProxy(port = 0, bindAddress = "127.0.0.1")
        proxy.start()
    }

    @AfterTest
    fun tearDown() {
        proxy.stop()
        runCatching { echo.close() }
    }

    private fun handshake(socket: Socket): DataInputStream {
        val out = socket.getOutputStream()
        out.write(byteArrayOf(5, 1, 0))
        out.flush()

        val input = DataInputStream(socket.getInputStream())
        assertEquals(5, input.readUnsignedByte(), "the proxy should answer SOCKS5")
        assertEquals(0, input.readUnsignedByte(), "no-auth should be accepted")
        return input
    }

    private fun connect(socket: Socket, host: String, port: Int, addressType: Int = 1) {
        val out = socket.getOutputStream()
        val header = mutableListOf<Byte>(5, 1, 0, addressType.toByte())
        when (addressType) {
            1 -> host.split(".").forEach { header.add(it.toInt().toByte()) }
            3 -> {
                header.add(host.length.toByte())
                header.addAll(host.toByteArray().toList())
            }
        }
        header.add((port shr 8).toByte())
        header.add(port.toByte())
        out.write(header.toByteArray())
        out.flush()
    }

    private fun readReply(input: DataInputStream): Int {
        assertEquals(5, input.readUnsignedByte())
        val code = input.readUnsignedByte()
        input.readUnsignedByte() // reserved
        val atyp = input.readUnsignedByte()
        input.skipBytes(if (atyp == 4) 16 else 4)
        input.skipBytes(2)
        return code
    }

    @Test
    fun `relays a connection to an ipv4 target`() {
        Socket("127.0.0.1", proxy.boundPort).use { socket ->
            val input = handshake(socket)
            connect(socket, "127.0.0.1", echoPort)
            assertEquals(0, readReply(input), "CONNECT should succeed")

            socket.getOutputStream().write("through the bond".toByteArray())
            socket.getOutputStream().flush()

            val buffer = ByteArray(16)
            input.readFully(buffer)
            assertEquals("through the bond", String(buffer))
        }
    }

    @Test
    fun `resolves and relays a domain name target`() {
        Socket("127.0.0.1", proxy.boundPort).use { socket ->
            val input = handshake(socket)
            connect(socket, "localhost", echoPort, addressType = 3)
            assertEquals(0, readReply(input))

            socket.getOutputStream().write("by name".toByteArray())
            socket.getOutputStream().flush()

            val buffer = ByteArray(7)
            input.readFully(buffer)
            assertEquals("by name", String(buffer))
        }
    }

    @Test
    fun `carries a payload larger than one buffer intact`() {
        Socket("127.0.0.1", proxy.boundPort).use { socket ->
            val input = handshake(socket)
            connect(socket, "127.0.0.1", echoPort)
            assertEquals(0, readReply(input))

            val payload = ByteArray(200_000) { (it % 251).toByte() }
            thread(isDaemon = true) {
                socket.getOutputStream().write(payload)
                socket.getOutputStream().flush()
            }

            val received = ByteArray(payload.size)
            input.readFully(received)
            assertTrue(payload.contentEquals(received), "the relayed bytes should be unchanged")
        }
    }

    @Test
    fun `refuses a command other than connect`() {
        Socket("127.0.0.1", proxy.boundPort).use { socket ->
            val input = handshake(socket)
            // BIND, which is not offered.
            socket.getOutputStream().write(byteArrayOf(5, 2, 0, 1, 127, 0, 0, 1, 0, 80))
            socket.getOutputStream().flush()

            assertEquals(7, readReply(input), "should answer 'command not supported'")
        }
    }

    @Test
    fun `refuses a client that will not do no-auth`() {
        Socket("127.0.0.1", proxy.boundPort).use { socket ->
            // Offers only username/password.
            socket.getOutputStream().write(byteArrayOf(5, 1, 2))
            socket.getOutputStream().flush()

            val input = DataInputStream(socket.getInputStream())
            assertEquals(5, input.readUnsignedByte())
            assertEquals(0xFF, input.readUnsignedByte(), "should answer 'no acceptable methods'")
        }
    }

    @Test
    fun `reports an unreachable target rather than hanging`() {
        Socket("127.0.0.1", proxy.boundPort).use { socket ->
            val input = handshake(socket)
            // Port 1 on loopback: nothing listens there, so connect is refused.
            connect(socket, "127.0.0.1", 1)

            assertEquals(4, readReply(input), "should answer 'host unreachable'")
        }
    }

    @Test
    fun `serves several clients at once`() {
        val threads = (1..8).map { n ->
            thread {
                Socket("127.0.0.1", proxy.boundPort).use { socket ->
                    val input = handshake(socket)
                    connect(socket, "127.0.0.1", echoPort)
                    assertEquals(0, readReply(input))

                    val message = "client-$n"
                    socket.getOutputStream().write(message.toByteArray())
                    socket.getOutputStream().flush()

                    val buffer = ByteArray(message.length)
                    input.readFully(buffer)
                    assertEquals(message, String(buffer))
                }
            }
        }
        threads.forEach { it.join(10_000) }
    }

    @Test
    fun `listens on all interfaces so hotspot clients can reach it`() {
        // Bound to 0.0.0.0, a client arriving over another interface is served.
        val open = SocksProxy(port = 0, bindAddress = "0.0.0.0")
        open.start()
        try {
            Socket(InetAddress.getLocalHost(), open.boundPort).use { socket ->
                handshake(socket)
            }
        } finally {
            open.stop()
        }
    }
}

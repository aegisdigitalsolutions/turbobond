package com.aegisdigital.turbobond

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.aegisdigital.turbobond.core.BondException
import com.aegisdigital.turbobond.core.FrameType
import com.aegisdigital.turbobond.core.Protocol
import com.aegisdigital.turbobond.core.ReorderBuffer
import com.aegisdigital.turbobond.core.Sealer
import com.aegisdigital.turbobond.core.SocksProxy
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

/**
 * The client half of the bond, as an Android VPN.
 *
 * Reads IP packets from the system's TUN interface, spreads them across every
 * available radio as sealed datagrams, and writes the concentrator's replies
 * back in order. This is the same wire protocol the Linux client speaks, so
 * either can talk to the same concentrator.
 *
 * What this does not do is cover other devices. Android forwards tethered and
 * hotspot traffic in the kernel, outside the VpnService interface, so packets
 * from a laptop or tablet on this phone's hotspot never reach this code.
 */
class BondVpnService : VpnService() {

    private val running = AtomicBoolean(false)
    private val pairing = AtomicBoolean(false)
    private val sequence = AtomicLong(0)
    private val lastHeard = AtomicLong(0)
    private var tunnel: ParcelFileDescriptor? = null
    private var uplinkManager: UplinkManager? = null
    private var proxy: SocksProxy? = null
    private var sessionId = 0
    private val threads = mutableListOf<Thread>()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopTunnel()
            stopSelf()
            return START_NOT_STICKY
        }
        if (running.get()) return START_STICKY

        val settings = Settings.load(this)
        if (!settings.isComplete) {
            Log.w(TAG, "not configured; open the app and enter the concentrator details")
            stopSelf()
            return START_NOT_STICKY
        }
        startForeground(NOTIFICATION_ID, notification("Connecting..."))
        startTunnel(settings)
        return START_STICKY
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopTunnel()
        super.onRevoke()
    }

    private fun startTunnel(settings: Settings) {
        val sealer = try {
            Sealer.fromPsk(settings.psk)
        } catch (exc: BondException) {
            Log.e(TAG, "bad pre-shared key: ${exc.message}")
            Status.publish(this, "Bad pre-shared key")
            stopSelf()
            return
        }

        sessionId = (System.nanoTime() and 0x7FFFFFFF).toInt()

        val manager = UplinkManager(this) { onUplinksChanged() }
        manager.protector = { socket -> protect(socket) }
        uplinkManager = manager
        manager.start()

        pairing.set(true)
        threads += thread(name = "tbond-pair") { pairThenEstablish(sealer, settings) }
    }

    /**
     * Reach the concentrator first, and only then capture the phone's traffic.
     *
     * Establishing the interface up front is the obvious order and the wrong
     * one: it installs a default route through a tunnel that may have no
     * working far end, so an unreachable server, a closed UDP port or a
     * mistyped key all present as the phone losing the internet entirely, with
     * nothing to say why. Handshaking first costs a few seconds and means a
     * failure leaves the connection untouched.
     */
    private fun pairThenEstablish(sealer: Sealer, settings: Settings) {
        val host = try {
            InetAddress.getByName(settings.host)
        } catch (exc: Exception) {
            Log.e(TAG, "cannot resolve ${settings.host}: ${exc.message}")
            fail("Cannot find ${settings.host}")
            return
        }

        val deadline = System.currentTimeMillis() + settings.pairTimeoutMs
        val buffer = ByteArray(Protocol.MAX_DATAGRAM)
        var sawUplink = false

        while (pairing.get() && System.currentTimeMillis() < deadline) {
            val links = uplinkManager?.uplinks.orEmpty()
            if (links.isEmpty()) {
                Thread.sleep(200)
                continue
            }
            if (!sawUplink) {
                sawUplink = true
                Status.publish(this, "Reaching ${settings.host}...")
            }

            for (uplink in links) {
                send(sealer, uplink, FrameType.HANDSHAKE, host, settings.port, 0, ByteArray(0))
            }
            for (uplink in links) {
                val datagram = DatagramPacket(buffer, buffer.size)
                try {
                    uplink.socket.soTimeout = PAIR_POLL_MS
                    uplink.socket.receive(datagram)
                } catch (_: Exception) {
                    continue
                }
                val frame = Protocol.decode(sealer, buffer.copyOf(datagram.length)) ?: continue
                if (frame.type == FrameType.HANDSHAKE_ACK) {
                    uplink.acked = true
                    uplink.lastSeen = System.currentTimeMillis()
                    Log.i(TAG, "$uplink paired; bringing up the interface")
                    establish(sealer, host, settings)
                    return
                }
            }
        }

        if (!pairing.get()) return
        Log.w(TAG, "no reply from ${settings.host}:${settings.port} in ${settings.pairTimeoutMs}ms")
        fail(
            if (!sawUplink) "No usable network"
            else "No reply from ${settings.host}:${settings.port}",
        )
    }

    /** Report why the bond did not come up, without having touched routing. */
    private fun fail(reason: String) {
        pairing.set(false)
        stopTunnel(reason)
        runCatching {
            (getSystemService(NotificationManager::class.java))
                .notify(NOTIFICATION_ID, notification(reason))
        }
        stopSelf()
    }

    private fun establish(sealer: Sealer, host: InetAddress, settings: Settings) {
        pairing.set(false)

        val descriptor = Builder()
            .setSession("turbobond")
            .addAddress(TUNNEL_ADDRESS, 30)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
            .addDnsServer("8.8.8.8")
            .setMtu(settings.tunnelMtu)
            .setConfigureIntent(
                PendingIntent.getActivity(
                    this, 0, Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                ),
            )
            .establish()

        if (descriptor == null) {
            Log.e(TAG, "the system refused to establish the tunnel")
            fail("Permission refused")
            return
        }

        tunnel = descriptor
        lastHeard.set(System.currentTimeMillis())
        running.set(true)

        val reorder = ReorderBuffer(timeoutMs = REORDER_MS)

        threads += thread(name = "tbond-tun") { pumpTun(descriptor, sealer, host, settings) }
        threads += thread(name = "tbond-net") { pumpNetwork(descriptor, sealer, reorder) }
        threads += thread(name = "tbond-keepalive") { keepalive(sealer, host, settings.port, settings.keepaliveMs) }
        threads += thread(name = "tbond-watchdog") { watchdog(settings.silenceLimitMs) }

        startProxy(settings.proxyPort)
        onUplinksChanged()
    }

    /**
     * Give the phone its connection back if the far end disappears.
     *
     * Once the interface is up the default route points into it, so a
     * concentrator that stops answering does not degrade the connection, it
     * removes it. Holding the tunnel open in that state is worse than not
     * having it, so the bond is torn down after every link has been silent long
     * enough that it is clearly not a passing blip.
     */
    private fun watchdog(silenceLimitMs: Long) {
        while (running.get()) {
            Thread.sleep(WATCHDOG_POLL_MS)
            if (!running.get()) return
            // Measured from the last datagram over any link, seeded at
            // establish, so links being torn down and replaced cannot leave the
            // clock stuck at zero and the tunnel up forever.
            if (System.currentTimeMillis() - lastHeard.get() < silenceLimitMs) continue
            Log.w(TAG, "no reply from the concentrator in ${silenceLimitMs}ms; releasing the tunnel")
            fail("Server stopped responding")
            return
        }
    }

    /**
     * Serve the bond to devices that cannot run the client.
     *
     * The proxy's onward sockets are deliberately *not* passed to protect(),
     * which is the whole point: unprotected sockets go through our own tunnel,
     * so a tablet's connection arrives here over the hotspot and leaves
     * bonded. Protecting them would send it out over one radio, unbonded, and
     * the tablet would be no better off than before.
     */
    private fun startProxy(port: Int) {
        if (port <= 0) return
        try {
            proxy = SocksProxy(port = port).also { it.start() }
            Log.i(TAG, "SOCKS5 proxy listening on $port")
        } catch (exc: Exception) {
            Log.w(TAG, "could not start the proxy on $port: ${exc.message}")
            proxy = null
        }
    }

    /** Phone to concentrator: read the TUN and spread packets across the radios. */
    private fun pumpTun(descriptor: ParcelFileDescriptor, sealer: Sealer, host: InetAddress, settings: Settings) {
        val input = FileInputStream(descriptor.fileDescriptor)
        val buffer = ByteArray(settings.tunnelMtu + 128)
        var cursor = 0

        while (running.get()) {
            val read = try {
                input.read(buffer)
            } catch (exc: Exception) {
                if (running.get()) Log.w(TAG, "tun read failed: ${exc.message}")
                break
            }
            if (read <= 0) continue

            val links = uplinkManager?.uplinks.orEmpty()
            if (links.isEmpty()) continue

            val packet = buffer.copyOf(read)
            val seq = sequence.getAndIncrement()

            // Round robin. Weighting by measured quality is what the Linux
            // client does; this keeps it simple until the app can measure.
            val uplink = links[cursor++ % links.size]
            send(sealer, uplink, FrameType.DATA, host, settings.port, seq, packet)

            // Small packets are cheap to duplicate and are usually signalling,
            // where a single loss is expensive. This is what keeps a call up
            // when one radio drops a packet.
            if (packet.size <= DUPLICATE_UNDER && links.size > 1) {
                for (other in links) {
                    if (other !== uplink) send(sealer, other, FrameType.DATA, host, settings.port, seq, packet)
                }
            }
        }
    }

    /** Concentrator to phone: decode, resequence, and write to the TUN. */
    private fun pumpNetwork(descriptor: ParcelFileDescriptor, sealer: Sealer, reorder: ReorderBuffer) {
        val output = FileOutputStream(descriptor.fileDescriptor)
        val buffer = ByteArray(Protocol.MAX_DATAGRAM)

        while (running.get()) {
            val links = uplinkManager?.uplinks.orEmpty()
            if (links.isEmpty()) {
                Thread.sleep(200)
                continue
            }
            for (uplink in links) {
                val datagram = DatagramPacket(buffer, buffer.size)
                try {
                    uplink.socket.soTimeout = 50
                    uplink.socket.receive(datagram)
                } catch (_: Exception) {
                    continue
                }
                val frame = Protocol.decode(sealer, buffer.copyOf(datagram.length)) ?: continue
                // Only authenticated datagrams count as the far end being
                // alive, so stray traffic to this port cannot hold the
                // watchdog off a tunnel that is actually dead.
                val now = System.currentTimeMillis()
                uplink.lastSeen = now
                lastHeard.set(now)

                when (frame.type) {
                    FrameType.HANDSHAKE_ACK -> {
                        if (!uplink.acked) {
                            uplink.acked = true
                            Log.i(TAG, "$uplink joined the bond")
                            onUplinksChanged()
                        }
                    }
                    FrameType.DATA -> {
                        if (frame.payload.isNotEmpty()) {
                            for (out in reorder.push(frame.seq, frame.payload)) {
                                runCatching { output.write(out) }
                            }
                        }
                    }
                    else -> Unit
                }
            }
            for (out in reorder.tick()) {
                runCatching { output.write(out) }
            }
        }
    }

    /**
     * Handshake new uplinks and keep the carrier's NAT mapping alive.
     *
     * Mobile networks reap idle UDP mappings within a minute or two. Without
     * this the concentrator's replies would stop reaching the phone as soon as
     * traffic went quiet.
     */
    private fun keepalive(sealer: Sealer, host: InetAddress, port: Int, keepaliveMs: Long) {
        while (running.get()) {
            for (uplink in uplinkManager?.uplinks.orEmpty()) {
                val type = if (uplink.acked) FrameType.KEEPALIVE else FrameType.HANDSHAKE
                send(sealer, uplink, type, host, port, 0, ByteArray(0))
            }
            Thread.sleep(keepaliveMs)
        }
    }

    private fun send(
        sealer: Sealer,
        uplink: Uplink,
        type: FrameType,
        host: InetAddress,
        port: Int,
        seq: Long,
        payload: ByteArray,
    ) {
        try {
            val datagram = Protocol.encode(
                sealer, type, sessionId, uplink.id, uplink.nextCounter(), seq, payload,
            )
            uplink.socket.send(DatagramPacket(datagram, datagram.size, host, port))
        } catch (exc: Exception) {
            Log.w(TAG, "send over $uplink failed: ${exc.message}")
        }
    }

    private fun onUplinksChanged() {
        val links = uplinkManager?.uplinks.orEmpty()
        val joined = links.count { it.acked }
        val text = when {
            links.isEmpty() -> "No uplinks"
            joined == 0 -> "${links.size} uplink(s), pairing..."
            else -> "Bonded over $joined of ${links.size}: " + links.joinToString(", ") { it.transport }
        }
        Status.publishProxy(LocalAddress.find(), proxy?.boundPort ?: 0)
        Status.publish(this, text)
        runCatching {
            (getSystemService(NotificationManager::class.java))
                .notify(NOTIFICATION_ID, notification(text))
        }
    }

    private fun stopTunnel(reason: String = "Disconnected") {
        // Pairing runs before the interface exists, so 'running' alone would
        // leave the uplinks and their network requests behind when a pair that
        // never completed is cancelled.
        val wasRunning = running.getAndSet(false)
        val wasPairing = pairing.getAndSet(false)
        if (!wasRunning && !wasPairing) return
        runCatching { proxy?.stop() }
        proxy = null
        uplinkManager?.stop()
        uplinkManager = null
        // Not the caller: fail() runs on one of these, and interrupting it here
        // would land the interrupt on whatever it did next instead.
        threads.filter { it !== Thread.currentThread() }.forEach { it.interrupt() }
        threads.clear()
        runCatching { tunnel?.close() }
        tunnel = null
        Status.publish(this, reason)
    }

    private fun notification(text: String): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "turbobond", NotificationManager.IMPORTANCE_LOW),
            )
        }
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("turbobond")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_upload)
            .setOngoing(true)
            .setContentIntent(
                PendingIntent.getActivity(
                    this, 0, Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                ),
            )
            .build()
    }

    companion object {
        const val TAG = "turbobond"
        const val ACTION_STOP = "com.aegisdigital.turbobond.STOP"
        private const val CHANNEL_ID = "turbobond"
        private const val NOTIFICATION_ID = 1
        private const val TUNNEL_ADDRESS = "10.77.0.2"
        private const val REORDER_MS = 90L
        private const val DUPLICATE_UNDER = 260

        private const val PAIR_POLL_MS = 250
        private const val WATCHDOG_POLL_MS = 5_000L
    }
}

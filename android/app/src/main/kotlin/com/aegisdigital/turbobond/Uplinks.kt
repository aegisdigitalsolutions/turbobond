package com.aegisdigital.turbobond

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import java.net.DatagramSocket
import java.util.concurrent.ConcurrentHashMap

/**
 * One uplink: a socket pinned to a specific radio.
 *
 * The socket is bound to its [Network] so packets written to it leave over that
 * radio specifically, rather than over whichever one Android currently
 * considers the default. Without that binding every socket would follow the
 * default route, all traffic would leave over one link, and there would be no
 * bond.
 */
class Uplink(
    val id: Int,
    val transport: String,
    val network: Network,
    val socket: DatagramSocket,
) {
    @Volatile var counter: Long = 0
    @Volatile var lastSeen: Long = 0
    @Volatile var acked: Boolean = false

    fun nextCounter(): Long = ++counter

    override fun toString(): String = "$transport(link $id)"
}

/**
 * Tracks the radios that are currently usable and keeps one uplink per radio.
 *
 * Android will happily keep WiFi and cellular up at the same time, but only if
 * something asks: requesting a cellular network explicitly is what stops the
 * system tearing the radio down once WiFi is connected. That request is the
 * whole reason this works on an unrooted phone.
 */
class UplinkManager(
    context: Context,
    private val onChange: () -> Unit,
) {
    private val connectivity =
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    private val callbacks = mutableListOf<ConnectivityManager.NetworkCallback>()
    private val byNetwork = ConcurrentHashMap<Network, Uplink>()
    private var nextId = 1

    val uplinks: List<Uplink> get() = byNetwork.values.sortedBy { it.id }

    /** Sockets need protecting before use, or their packets re-enter the tunnel. */
    var protector: ((DatagramSocket) -> Boolean)? = null

    fun start() {
        request(NetworkCapabilities.TRANSPORT_WIFI, "wifi")
        request(NetworkCapabilities.TRANSPORT_CELLULAR, "cellular")
        request(NetworkCapabilities.TRANSPORT_ETHERNET, "ethernet")
    }

    fun stop() {
        callbacks.forEach {
            runCatching { connectivity.unregisterNetworkCallback(it) }
        }
        callbacks.clear()
        byNetwork.values.forEach { runCatching { it.socket.close() } }
        byNetwork.clear()
    }

    private fun request(transport: Int, label: String) {
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addTransportType(transport)
            .build()

        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (byNetwork.containsKey(network)) return
                val socket = DatagramSocket()
                // Order matters: protect() keeps this socket outside our own
                // tunnel, and bindSocket() pins it to this radio. Skipping the
                // first would loop the tunnel through itself.
                val protectedOk = protector?.invoke(socket) ?: false
                if (!protectedOk) {
                    Log.w(TAG, "could not protect the $label socket; skipping this uplink")
                    runCatching { socket.close() }
                    return
                }
                try {
                    network.bindSocket(socket)
                } catch (exc: Exception) {
                    Log.w(TAG, "could not bind a socket to $label: ${exc.message}")
                    runCatching { socket.close() }
                    return
                }
                val uplink = Uplink(nextId++, label, network, socket)
                byNetwork[network] = uplink
                Log.i(TAG, "uplink up: $uplink")
                onChange()
            }

            override fun onLost(network: Network) {
                byNetwork.remove(network)?.let {
                    Log.i(TAG, "uplink lost: $it")
                    runCatching { it.socket.close() }
                    onChange()
                }
            }
        }

        callbacks += callback
        runCatching { connectivity.requestNetwork(request, callback) }
            .onFailure { Log.w(TAG, "could not request $label: ${it.message}") }
    }

    companion object {
        const val TAG = "turbobond"
    }
}

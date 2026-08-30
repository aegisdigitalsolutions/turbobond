package com.aegisdigital.turbobond

import android.content.Context
import android.content.Intent

/** The three values the concentrator's installer prints. */
data class Settings(
    val host: String = "",
    val port: Int = 5310,
    val psk: String = "",
    /** Where other devices reach the bond. Zero turns the proxy off. */
    val proxyPort: Int = 1080,
) {
    val isComplete: Boolean get() = host.isNotBlank() && psk.isNotBlank() && port in 1..65535

    companion object {
        private const val FILE = "turbobond"

        fun load(context: Context): Settings {
            val prefs = context.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            return Settings(
                host = prefs.getString("host", "").orEmpty(),
                port = prefs.getInt("port", 5310),
                psk = prefs.getString("psk", "").orEmpty(),
                proxyPort = prefs.getInt("proxyPort", 1080),
            )
        }

        fun save(context: Context, settings: Settings) {
            context.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit()
                .putString("host", settings.host.trim())
                .putInt("port", settings.port)
                .putString("psk", settings.psk.trim())
                .putInt("proxyPort", settings.proxyPort)
                .apply()
        }
    }
}

/** Carries the tunnel's state back to the activity, which may not be running. */
object Status {
    const val ACTION = "com.aegisdigital.turbobond.STATUS"
    const val EXTRA = "text"

    @Volatile
    var latest: String = "Disconnected"
        private set

    /** What to type into a proxy client on another device. */
    @Volatile
    var proxyAddress: String = ""
        private set

    fun publish(context: Context, text: String) {
        latest = text
        context.sendBroadcast(Intent(ACTION).setPackage(context.packageName).putExtra(EXTRA, text))
    }

    fun publishProxy(address: String, port: Int) {
        proxyAddress = if (address.isNotBlank() && port > 0) "$address:$port" else ""
    }
}

/**
 * The address other devices use to reach this phone.
 *
 * When the hotspot is on, Android gives it its own interface, and that is the
 * address a tablet has to point its proxy client at. The phone's mobile or WiFi
 * address is not reachable from the hotspot's network, so picking the wrong one
 * produces a setting that silently never connects.
 */
object LocalAddress {
    private val HOTSPOT_PREFIXES = listOf("192.168.", "172.", "10.")

    fun find(): String {
        val candidates = buildList {
            val interfaces = runCatching { java.net.NetworkInterface.getNetworkInterfaces() }
                .getOrNull() ?: return ""
            for (nic in interfaces) {
                if (!nic.isUp || nic.isLoopback) continue
                // Our own tunnel is not somewhere another device can connect.
                if (nic.name.startsWith("tun")) continue
                for (address in nic.inetAddresses) {
                    val host = address.hostAddress ?: continue
                    if (address.isLoopbackAddress || host.contains(":")) continue
                    add(nic.name to host)
                }
            }
        }
        // Prefer the tethering interface, then any private address.
        return candidates.firstOrNull { (name, _) -> name.startsWith("ap") || name.startsWith("swlan") }?.second
            ?: candidates.firstOrNull { (_, host) -> HOTSPOT_PREFIXES.any { host.startsWith(it) } }?.second
            ?: candidates.firstOrNull()?.second
            ?: ""
    }
}

package com.aegisdigital.turbobond

import android.content.Context
import android.content.Intent

/** The three values the concentrator's installer prints. */
data class Settings(
    val host: String = "",
    val port: Int = 5310,
    val psk: String = "",
    /** Built-in profile, or Custom when manually tuned. */
    val profileName: String = ConnectionProfiles.CUSTOM,
    /** Where other devices reach the bond. Zero turns the proxy off. */
    val proxyPort: Int = 1080,
    /** DNS resolvers announced inside the VPN. Blank falls back to defaults. */
    val dnsPrimary: String = "1.1.1.1",
    val dnsSecondary: String = "8.8.8.8",
    /** VPN interface MTU. */
    val tunnelMtu: Int = 1380,
    /** Duplicate packets at or below this size across all uplinks. */
    val duplicateUnderBytes: Int = 260,
    /** Handshake timeout before giving up. */
    val pairTimeoutMs: Long = 20_000L,
    /** Keepalive interval while connected. */
    val keepaliveMs: Long = 15_000L,
    /** Release the tunnel if nothing authenticated arrives for this long. */
    val silenceLimitMs: Long = 75_000L,
) {
    val isComplete: Boolean get() = host.isNotBlank() && psk.isNotBlank() && port in 1..65535

    fun normalized(): Settings = copy(
        profileName = profileName.takeIf { ConnectionProfiles.NAMES.contains(it) } ?: ConnectionProfiles.CUSTOM,
        port = port.coerceIn(1, 65535),
        proxyPort = proxyPort.coerceIn(0, 65535),
        tunnelMtu = tunnelMtu.coerceIn(576, 9000),
        duplicateUnderBytes = duplicateUnderBytes.coerceIn(0, 1500),
        pairTimeoutMs = pairTimeoutMs.coerceIn(3_000L, 120_000L),
        keepaliveMs = keepaliveMs.coerceIn(5_000L, 60_000L),
        silenceLimitMs = silenceLimitMs.coerceIn(15_000L, 300_000L),
    )

    companion object {
        private const val FILE = "turbobond"

        fun load(context: Context): Settings {
            val prefs = context.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            return Settings(
                host = prefs.getString("host", "").orEmpty(),
                port = prefs.getInt("port", 5310),
                psk = prefs.getString("psk", "").orEmpty(),
                profileName = prefs.getString("profileName", ConnectionProfiles.CUSTOM).orEmpty(),
                proxyPort = prefs.getInt("proxyPort", 1080),
                dnsPrimary = prefs.getString("dnsPrimary", "1.1.1.1").orEmpty(),
                dnsSecondary = prefs.getString("dnsSecondary", "8.8.8.8").orEmpty(),
                tunnelMtu = prefs.getInt("tunnelMtu", 1380),
                duplicateUnderBytes = prefs.getInt("duplicateUnderBytes", 260),
                pairTimeoutMs = prefs.getLong("pairTimeoutMs", 20_000L),
                keepaliveMs = prefs.getLong("keepaliveMs", 15_000L),
                silenceLimitMs = prefs.getLong("silenceLimitMs", 75_000L),
            ).normalized()
        }

        fun save(context: Context, settings: Settings) {
            val normalized = settings.normalized()
            context.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit()
                .putString("host", normalized.host.trim())
                .putInt("port", normalized.port)
                .putString("psk", normalized.psk.trim())
                .putString("profileName", normalized.profileName)
                .putInt("proxyPort", normalized.proxyPort)
                .putString("dnsPrimary", normalized.dnsPrimary.trim())
                .putString("dnsSecondary", normalized.dnsSecondary.trim())
                .putInt("tunnelMtu", normalized.tunnelMtu)
                .putInt("duplicateUnderBytes", normalized.duplicateUnderBytes)
                .putLong("pairTimeoutMs", normalized.pairTimeoutMs)
                .putLong("keepaliveMs", normalized.keepaliveMs)
                .putLong("silenceLimitMs", normalized.silenceLimitMs)
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

    @Volatile
    var diagnostics: String = "No diagnostics yet"
        private set

    fun publish(context: Context, text: String) {
        latest = text
        context.sendBroadcast(Intent(ACTION).setPackage(context.packageName).putExtra(EXTRA, text))
    }

    fun publishProxy(address: String, port: Int) {
        proxyAddress = if (address.isNotBlank() && port > 0) "$address:$port" else ""
    }

    fun publishDiagnostics(context: Context, text: String) {
        diagnostics = text
        context.sendBroadcast(Intent(ACTION).setPackage(context.packageName).putExtra(EXTRA, latest))
    }
}

object ConnectionProfiles {
    const val CUSTOM = "Custom"
    const val MAX_SPEED = "Max Speed"
    const val STABILITY = "Stability"
    const val SIP_VOIP = "SIP/VoIP"
    const val STREAMING = "Streaming"

    val NAMES: List<String> = listOf(CUSTOM, MAX_SPEED, STABILITY, SIP_VOIP, STREAMING)

    fun applyProfile(name: String, base: Settings): Settings {
        val host = base.host
        val port = base.port
        val psk = base.psk
        return when (name) {
            MAX_SPEED -> base.copy(
                host = host,
                port = port,
                psk = psk,
                profileName = MAX_SPEED,
                dnsPrimary = "1.1.1.1",
                dnsSecondary = "8.8.8.8",
                tunnelMtu = 1420,
                duplicateUnderBytes = 140,
                pairTimeoutMs = 12_000L,
                keepaliveMs = 20_000L,
                silenceLimitMs = 90_000L,
            )
            STABILITY -> base.copy(
                host = host,
                port = port,
                psk = psk,
                profileName = STABILITY,
                dnsPrimary = "1.1.1.1",
                dnsSecondary = "9.9.9.9",
                tunnelMtu = 1360,
                duplicateUnderBytes = 320,
                pairTimeoutMs = 30_000L,
                keepaliveMs = 10_000L,
                silenceLimitMs = 120_000L,
            )
            SIP_VOIP -> base.copy(
                host = host,
                port = port,
                psk = psk,
                profileName = SIP_VOIP,
                dnsPrimary = "1.1.1.1",
                dnsSecondary = "1.0.0.1",
                tunnelMtu = 1320,
                duplicateUnderBytes = 640,
                pairTimeoutMs = 30_000L,
                keepaliveMs = 8_000L,
                silenceLimitMs = 150_000L,
            )
            STREAMING -> base.copy(
                host = host,
                port = port,
                psk = psk,
                profileName = STREAMING,
                dnsPrimary = "8.8.8.8",
                dnsSecondary = "1.1.1.1",
                tunnelMtu = 1400,
                duplicateUnderBytes = 220,
                pairTimeoutMs = 20_000L,
                keepaliveMs = 12_000L,
                silenceLimitMs = 120_000L,
            )
            else -> base.copy(profileName = CUSTOM)
        }.normalized()
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

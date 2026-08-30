package com.aegisdigital.turbobond

import android.content.Context
import android.content.Intent

/** The three values the concentrator's installer prints. */
data class Settings(
    val host: String = "",
    val port: Int = 5310,
    val psk: String = "",
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
            )
        }

        fun save(context: Context, settings: Settings) {
            context.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit()
                .putString("host", settings.host.trim())
                .putInt("port", settings.port)
                .putString("psk", settings.psk.trim())
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

    fun publish(context: Context, text: String) {
        latest = text
        context.sendBroadcast(Intent(ACTION).setPackage(context.packageName).putExtra(EXTRA, text))
    }
}

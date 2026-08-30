package com.aegisdigital.turbobond

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast

/**
 * Everything the app asks for: the three values the concentrator printed, and
 * a button.
 */
class MainActivity : Activity() {

    private lateinit var host: EditText
    private lateinit var port: EditText
    private lateinit var psk: EditText
    private lateinit var profile: Spinner
    private lateinit var proxyPort: EditText
    private lateinit var dnsPrimary: EditText
    private lateinit var dnsSecondary: EditText
    private lateinit var mtu: EditText
    private lateinit var duplicateUnder: EditText
    private lateinit var pairTimeout: EditText
    private lateinit var keepalive: EditText
    private lateinit var silenceLimit: EditText
    private lateinit var status: TextView
    private lateinit var proxy: TextView
    private lateinit var diagnostics: TextView

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            status.text = intent?.getStringExtra(Status.EXTRA) ?: Status.latest
            showProxy()
            showDiagnostics()
        }
    }

    private fun showProxy() {
        proxy.text = Status.proxyAddress.ifBlank { "not running" }
    }

    private fun showDiagnostics() {
        diagnostics.text = Status.diagnostics
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        host = findViewById(R.id.host)
        port = findViewById(R.id.port)
        psk = findViewById(R.id.psk)
        profile = findViewById(R.id.profile)
        proxyPort = findViewById(R.id.proxyPort)
        dnsPrimary = findViewById(R.id.dnsPrimary)
        dnsSecondary = findViewById(R.id.dnsSecondary)
        mtu = findViewById(R.id.mtu)
        duplicateUnder = findViewById(R.id.duplicateUnder)
        pairTimeout = findViewById(R.id.pairTimeout)
        keepalive = findViewById(R.id.keepalive)
        silenceLimit = findViewById(R.id.silenceLimit)
        status = findViewById(R.id.status)
        proxy = findViewById(R.id.proxy)
        diagnostics = findViewById(R.id.diagnostics)

        profile.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            ConnectionProfiles.NAMES,
        )

        val saved = Settings.load(this)
        fillFromSettings(saved)
        status.text = Status.latest
        showProxy()
        showDiagnostics()

        // Shown so a report of "it does nothing" can be tied to a build,
        // rather than guessing whether a fix is even installed.
        findViewById<TextView>(R.id.version).text = buildString {
            append("version ")
            append(BuildConfig.VERSION_NAME)
            append(" (build ")
            append(BuildConfig.VERSION_CODE)
            append(")")
        }

        findViewById<Button>(R.id.connect).setOnClickListener { connect() }
        findViewById<Button>(R.id.applyProfile).setOnClickListener { applySelectedProfile() }
        findViewById<Button>(R.id.disconnect).setOnClickListener {
            startService(Intent(this, BondVpnService::class.java).setAction(BondVpnService.ACTION_STOP))
        }
    }

    override fun onResume() {
        super.onResume()
        val filter = IntentFilter(Status.ACTION)
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(statusReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(statusReceiver, filter)
        }
        status.text = Status.latest
        showProxy()
        showDiagnostics()
    }

    override fun onPause() {
        super.onPause()
        runCatching { unregisterReceiver(statusReceiver) }
    }

    private fun connect() {
        val settings = readSettingsFromForm().normalized()
        if (!settings.isComplete) {
            Toast.makeText(this, "Enter the host, port and key from the server", Toast.LENGTH_LONG).show()
            return
        }
        Settings.save(this, settings)

        // The system asks the user to consent to the VPN the first time.
        val consent = VpnService.prepare(this)
        if (consent != null) {
            startActivityForResult(consent, REQUEST_VPN)
        } else {
            onActivityResult(REQUEST_VPN, RESULT_OK, null)
        }
    }

    private fun readSettingsFromForm(): Settings {
        return Settings(
            host = host.text.toString().trim(),
            port = port.text.toString().trim().toIntOrNull() ?: 0,
            psk = psk.text.toString().trim(),
            profileName = profile.selectedItem?.toString() ?: ConnectionProfiles.CUSTOM,
            proxyPort = proxyPort.text.toString().trim().toIntOrNull() ?: 1080,
            dnsPrimary = dnsPrimary.text.toString().trim(),
            dnsSecondary = dnsSecondary.text.toString().trim(),
            tunnelMtu = mtu.text.toString().trim().toIntOrNull() ?: 1380,
            duplicateUnderBytes = duplicateUnder.text.toString().trim().toIntOrNull() ?: 260,
            pairTimeoutMs = (pairTimeout.text.toString().trim().toLongOrNull() ?: 20L) * 1000L,
            keepaliveMs = (keepalive.text.toString().trim().toLongOrNull() ?: 15L) * 1000L,
            silenceLimitMs = (silenceLimit.text.toString().trim().toLongOrNull() ?: 75L) * 1000L,
        )
    }

    private fun fillFromSettings(settings: Settings) {
        host.setText(settings.host)
        port.setText(settings.port.toString())
        psk.setText(settings.psk)
        proxyPort.setText(settings.proxyPort.toString())
        dnsPrimary.setText(settings.dnsPrimary)
        dnsSecondary.setText(settings.dnsSecondary)
        mtu.setText(settings.tunnelMtu.toString())
        duplicateUnder.setText(settings.duplicateUnderBytes.toString())
        pairTimeout.setText((settings.pairTimeoutMs / 1000L).toString())
        keepalive.setText((settings.keepaliveMs / 1000L).toString())
        silenceLimit.setText((settings.silenceLimitMs / 1000L).toString())
        val index = ConnectionProfiles.NAMES.indexOf(settings.profileName).coerceAtLeast(0)
        profile.setSelection(index)
    }

    private fun applySelectedProfile() {
        val selected = profile.selectedItem?.toString() ?: ConnectionProfiles.CUSTOM
        val updated = ConnectionProfiles.applyProfile(selected, readSettingsFromForm())
        fillFromSettings(updated)
        Settings.save(this, updated)
        Toast.makeText(this, "Applied profile: $selected", Toast.LENGTH_SHORT).show()
    }

    @Deprecated("startActivityForResult is the only VpnService.prepare flow available")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQUEST_VPN) return
        if (resultCode != RESULT_OK) {
            status.text = "Permission refused"
            return
        }
        val effective = Settings.load(this)
        startService(Intent(this, BondVpnService::class.java))
        status.text = "Starting ${effective.host}:${effective.port} (${effective.profileName})..."
    }

    companion object {
        private const val REQUEST_VPN = 1
    }
}

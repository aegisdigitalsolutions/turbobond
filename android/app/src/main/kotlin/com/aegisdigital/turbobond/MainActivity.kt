package com.aegisdigital.turbobond

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
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
    private lateinit var proxyPort: EditText
    private lateinit var mtu: EditText
    private lateinit var pairTimeout: EditText
    private lateinit var keepalive: EditText
    private lateinit var silenceLimit: EditText
    private lateinit var status: TextView
    private lateinit var proxy: TextView

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            status.text = intent?.getStringExtra(Status.EXTRA) ?: Status.latest
            showProxy()
        }
    }

    private fun showProxy() {
        proxy.text = Status.proxyAddress.ifBlank { "not running" }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        host = findViewById(R.id.host)
        port = findViewById(R.id.port)
        psk = findViewById(R.id.psk)
        proxyPort = findViewById(R.id.proxyPort)
        mtu = findViewById(R.id.mtu)
        pairTimeout = findViewById(R.id.pairTimeout)
        keepalive = findViewById(R.id.keepalive)
        silenceLimit = findViewById(R.id.silenceLimit)
        status = findViewById(R.id.status)
        proxy = findViewById(R.id.proxy)

        val saved = Settings.load(this)
        host.setText(saved.host)
        port.setText(saved.port.toString())
        psk.setText(saved.psk)
        proxyPort.setText(saved.proxyPort.toString())
        mtu.setText(saved.tunnelMtu.toString())
        pairTimeout.setText((saved.pairTimeoutMs / 1000L).toString())
        keepalive.setText((saved.keepaliveMs / 1000L).toString())
        silenceLimit.setText((saved.silenceLimitMs / 1000L).toString())
        status.text = Status.latest
        showProxy()

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
    }

    override fun onPause() {
        super.onPause()
        runCatching { unregisterReceiver(statusReceiver) }
    }

    private fun connect() {
        val settings = Settings(
            host = host.text.toString().trim(),
            port = port.text.toString().trim().toIntOrNull() ?: 0,
            psk = psk.text.toString().trim(),
            proxyPort = proxyPort.text.toString().trim().toIntOrNull() ?: 1080,
            tunnelMtu = mtu.text.toString().trim().toIntOrNull() ?: 1380,
            pairTimeoutMs = (pairTimeout.text.toString().trim().toLongOrNull() ?: 20L) * 1000L,
            keepaliveMs = (keepalive.text.toString().trim().toLongOrNull() ?: 15L) * 1000L,
            silenceLimitMs = (silenceLimit.text.toString().trim().toLongOrNull() ?: 75L) * 1000L,
        ).normalized()
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
        status.text = "Starting ${effective.host}:${effective.port} (MTU ${effective.tunnelMtu})..."
    }

    companion object {
        private const val REQUEST_VPN = 1
    }
}

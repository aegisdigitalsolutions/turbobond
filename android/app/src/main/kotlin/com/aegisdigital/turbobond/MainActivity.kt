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
        status = findViewById(R.id.status)
        proxy = findViewById(R.id.proxy)

        val saved = Settings.load(this)
        host.setText(saved.host)
        port.setText(saved.port.toString())
        psk.setText(saved.psk)
        status.text = Status.latest
        showProxy()

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
        )
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
        startService(Intent(this, BondVpnService::class.java))
        status.text = "Starting..."
    }

    companion object {
        private const val REQUEST_VPN = 1
    }
}

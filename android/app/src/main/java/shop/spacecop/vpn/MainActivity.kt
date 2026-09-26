package shop.spacecop.vpn

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    private lateinit var uris: EditText
    private lateinit var dns: EditText
    private lateinit var discover: CheckBox
    private lateinit var status: TextView
    private lateinit var log: TextView
    private lateinit var connect: Button
    private lateinit var disconnect: Button
    private val ui = Handler(Looper.getMainLooper())
    private val prefs by lazy { getSharedPreferences("spacecop", MODE_PRIVATE) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        uris = findViewById(R.id.uris)
        dns = findViewById(R.id.dns)
        discover = findViewById(R.id.discover)
        status = findViewById(R.id.status)
        log = findViewById(R.id.log)
        connect = findViewById(R.id.connect)
        disconnect = findViewById(R.id.disconnect)

        uris.setText(prefs.getString("uris", ""))
        dns.setText(prefs.getString("dns", "1.1.1.1:53"))
        discover.isChecked = prefs.getBoolean("discover", true)

        connect.setOnClickListener { requestVpnPermissionAndStart() }
        disconnect.setOnClickListener {
            startService(Intent(this, SpaceCopVpnService::class.java).setAction(SpaceCopVpnService.ACTION_STOP))
        }
        ui.post(refresh)
    }

    private val refresh = object : Runnable {
        override fun run() {
            val on = SpaceCopVpnService.running
            status.text = if (on) getString(R.string.status_on) else getString(R.string.status_off)
            status.setTextColor(getColor(if (on) R.color.ok else R.color.err))
            connect.isEnabled = !on
            disconnect.isEnabled = on
            if (SpaceCopVpnService.lastLog.isNotEmpty()) log.text = SpaceCopVpnService.lastLog
            ui.postDelayed(this, 1000)
        }
    }

    private fun requestVpnPermissionAndStart() {
        val list = uris.text.toString().lines().map { it.trim() }.filter { it.startsWith("spacecop://") }
        if (list.isEmpty()) { log.text = getString(R.string.need_uri); return }
        prefs.edit().putString("uris", uris.text.toString())
            .putString("dns", dns.text.toString())
            .putBoolean("discover", discover.isChecked).apply()
        val intent = VpnService.prepare(this)
        if (intent != null) startActivityForResult(intent, 1) else onActivityResult(1, Activity.RESULT_OK, null)
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1 && resultCode == Activity.RESULT_OK) {
            val list = ArrayList(uris.text.toString().lines().map { it.trim() }.filter { it.startsWith("spacecop://") })
            val intent = Intent(this, SpaceCopVpnService::class.java)
                .setAction(SpaceCopVpnService.ACTION_START)
                .putStringArrayListExtra(SpaceCopVpnService.EXTRA_URIS, list)
                .putExtra(SpaceCopVpnService.EXTRA_DNS, dns.text.toString().ifBlank { "1.1.1.1:53" })
                .putExtra(SpaceCopVpnService.EXTRA_DISCOVER, discover.isChecked)
            startForegroundService(intent)
        }
    }
}

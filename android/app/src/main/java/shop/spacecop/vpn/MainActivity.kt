package shop.spacecop.vpn

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.google.android.material.button.MaterialButton
import org.json.JSONObject

class MainActivity : AppCompatActivity() {

    private lateinit var uris: EditText
    private lateinit var dns: EditText
    private lateinit var discover: CheckBox
    private lateinit var status: TextView
    private lateinit var stats: TextView
    private lateinit var nodes: TextView
    private lateinit var log: TextView
    private lateinit var logScroll: ScrollView
    private lateinit var connect: MaterialButton
    private lateinit var disconnect: MaterialButton
    private val ui = Handler(Looper.getMainLooper())
    private val prefs by lazy { getSharedPreferences("spacecop", MODE_PRIVATE) }
    private var lastLog = ""
    private var lastStatus = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        uris = findViewById(R.id.uris)
        dns = findViewById(R.id.dns)
        discover = findViewById(R.id.discover)
        status = findViewById(R.id.status)
        stats = findViewById(R.id.stats)
        nodes = findViewById(R.id.nodes)
        log = findViewById(R.id.log)
        logScroll = findViewById(R.id.log_scroll)
        connect = findViewById(R.id.connect)
        disconnect = findViewById(R.id.disconnect)

        uris.setText(prefs.getString("uris", ""))
        dns.setText(prefs.getString("dns", "1.1.1.1:53"))
        discover.isChecked = prefs.getBoolean("discover", true)

        connect.setOnClickListener { requestVpnPermissionAndStart() }
        disconnect.setOnClickListener {
            val i = Intent(this, SpaceCopVpnService::class.java).setAction(SpaceCopVpnService.ACTION_STOP)
            startService(i)
        }
        findViewById<MaterialButton>(R.id.clear_log).setOnClickListener {
            SpaceCopVpnService.clearLog(); lastLog = "\u0000"; log.text = ""
        }
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 2)
        }
    }

    override fun onResume() { super.onResume(); ui.post(refresh) }
    override fun onPause() { super.onPause(); ui.removeCallbacks(refresh) }

    private val refresh = object : Runnable {
        override fun run() {
            when (SpaceCopVpnService.state) {
                "on" -> { status.text = getString(R.string.status_on); status.setTextColor(getColor(R.color.ok)) }
                "connecting" -> { status.text = getString(R.string.status_connecting); status.setTextColor(getColor(R.color.warn)) }
                else -> { status.text = getString(R.string.status_off); status.setTextColor(getColor(R.color.err)) }
            }
            val on = SpaceCopVpnService.state != "off"
            connect.isEnabled = !on
            disconnect.isEnabled = on

            val text = SpaceCopVpnService.logText()
            if (text != lastLog) {
                lastLog = text
                log.text = if (text.isEmpty()) getString(R.string.log_empty) else text
                logScroll.post { logScroll.fullScroll(ScrollView.FOCUS_DOWN) }
            }
            val js = SpaceCopVpnService.statusJson
            if (js != lastStatus) { lastStatus = js; renderStatus(js) }
            ui.postDelayed(this, 1000)
        }
    }

    private fun renderStatus(js: String) {
        if (js.isEmpty()) {
            stats.text = getString(R.string.stats_idle)
            nodes.text = getString(R.string.nodes_idle)
            return
        }
        try {
            val o = JSONObject(js)
            if (o.has("error")) { stats.text = o.getString("error"); return }
            stats.text = getString(
                R.string.stats_fmt,
                o.optInt("nodes"), o.optInt("connections"), o.optInt("opened"), o.optInt("failed"),
                o.optInt("dns"), human(o.optLong("up")), human(o.optLong("down"))
            )
            val table = o.optJSONArray("table")
            if (table == null || table.length() == 0) { nodes.text = getString(R.string.nodes_idle); return }
            val sb = StringBuilder()
            var totalBytes = 0L
            for (i in 0 until table.length()) totalBytes += table.getJSONObject(i).optLong("bytes")
            for (i in 0 until table.length()) {
                val r = table.getJSONObject(i)
                val lat = if (r.isNull("latency_ms")) "—" else r.optInt("latency_ms").toString() + " мс"
                val bytes = r.optLong("bytes")
                val share = if (totalBytes > 0) (bytes * 100 / totalBytes).toString() + "%" else "0%"
                if (i > 0) sb.append("\n")
                sb.append(if (i == 0) "★ " else "  ")
                    .append(r.optString("addr")).append("\n    здоровье ").append(r.optDouble("health"))
                    .append(" · ").append(lat).append(" · запросов ").append(r.optInt("requests"))
                    .append(" (ошибок ").append(r.optInt("failures")).append(") · ")
                    .append(human(bytes)).append(" · ").append(share)
            }
            nodes.text = sb.toString()
        } catch (e: Exception) {
            stats.text = "status: ${e.message}"
        }
    }

    private fun human(n: Long): String = when {
        n >= 1L shl 30 -> String.format("%.1f ГБ", n / (1L shl 30).toDouble())
        n >= 1L shl 20 -> String.format("%.1f МБ", n / (1L shl 20).toDouble())
        n >= 1L shl 10 -> String.format("%.0f КБ", n / 1024.0)
        else -> "$n Б"
    }

    private fun uriList(): ArrayList<String> =
        ArrayList(uris.text.toString().lines().map { it.trim() }.filter { it.startsWith("spacecop://") })

    private fun requestVpnPermissionAndStart() {
        if (uriList().isEmpty()) {
            SpaceCopVpnService.appendLog(getString(R.string.need_uri)); return
        }
        prefs.edit().putString("uris", uris.text.toString())
            .putString("dns", dns.text.toString())
            .putBoolean("discover", discover.isChecked).apply()
        val intent = VpnService.prepare(this)
        if (intent != null) startActivityForResult(intent, 1) else onActivityResult(1, Activity.RESULT_OK, null)
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != 1) return
        if (resultCode != Activity.RESULT_OK) {
            SpaceCopVpnService.appendLog(getString(R.string.vpn_denied)); return
        }
        val intent = Intent(this, SpaceCopVpnService::class.java)
            .setAction(SpaceCopVpnService.ACTION_START)
            .putStringArrayListExtra(SpaceCopVpnService.EXTRA_URIS, uriList())
            .putExtra(SpaceCopVpnService.EXTRA_DNS, dns.text.toString().ifBlank { "1.1.1.1:53" })
            .putExtra(SpaceCopVpnService.EXTRA_DISCOVER, discover.isChecked)
        ContextCompat.startForegroundService(this, intent)
    }
}

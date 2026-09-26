package shop.spacecop.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import com.chaquo.python.PyObject
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import java.text.SimpleDateFormat
import java.util.ArrayDeque
import java.util.Date
import java.util.Locale

/** Receives log lines from Python (Chaquopy calls the public `log` method). */
class PyLogger {
    fun log(line: String) {
        SpaceCopVpnService.appendLog(line)
    }
}

/** Lets Python mark its UDP socket as "outside the tunnel" (VpnService.protect). */
class SocketProtector(private val service: VpnService) {
    fun protectFd(fd: Int): Boolean = service.protect(fd)
}

/**
 * Full-system VPN: obtains the TUN file descriptor from Android and hands it to
 * the SpaceCopVPN packet engine (spacecop.tun.android.run_engine), which
 * terminates TCP/DNS and carries everything through the overlay.
 */
class SpaceCopVpnService : VpnService() {

    companion object {
        const val ACTION_START = "shop.spacecop.vpn.START"
        const val ACTION_STOP = "shop.spacecop.vpn.STOP"
        const val EXTRA_URIS = "uris"
        const val EXTRA_DNS = "dns"
        const val EXTRA_DISCOVER = "discover"
        private const val CHANNEL = "spacecop_vpn"
        private const val TAG = "SpaceCopVPN"
        private const val LOG_KEEP = 300

        /** "off", "connecting", "on" — read by the activity. */
        @Volatile var state: String = "off"
        /** Last status JSON from the engine (nodes, connections, traffic, table). */
        @Volatile var statusJson: String = ""

        private val logLines = ArrayDeque<String>()
        private val stamp = SimpleDateFormat("HH:mm:ss", Locale.US)

        fun appendLog(line: String) {
            val text = stamp.format(Date()) + " " + line
            synchronized(logLines) {
                logLines.addLast(text)
                while (logLines.size > LOG_KEEP) logLines.removeFirst()
            }
            Log.i(TAG, line)
        }

        fun logText(): String = synchronized(logLines) { logLines.joinToString("\n") }

        fun clearLog() = synchronized(logLines) { logLines.clear() }
    }

    private var tun: ParcelFileDescriptor? = null
    private var handle: PyObject? = null
    private var poller: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> { stopVpn(); return START_NOT_STICKY }
            ACTION_START, null -> {
                val uris = intent?.getStringArrayListExtra(EXTRA_URIS) ?: arrayListOf()
                val dns = intent?.getStringExtra(EXTRA_DNS) ?: "1.1.1.1:53"
                val discover = intent?.getBooleanExtra(EXTRA_DISCOVER, true) ?: true
                startVpn(uris, dns, discover)
            }
        }
        return START_STICKY
    }

    private fun startVpn(uris: List<String>, dns: String, discover: Boolean) {
        if (state != "off") return
        state = "connecting"
        clearLog()
        appendLog("запуск VPN…")
        startForeground(1, buildNotification("Подключение…"))

        val builder = Builder()
            .setSession("SpaceCopVPN")
            .addAddress("10.77.0.2", 24)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("10.77.0.1")
            .setMtu(1400)
            .setBlocking(true)
        // Keep our own app out of the tunnel so the UDP packets to the nodes
        // leave through the real network (also covered by protect() below).
        try { builder.addDisallowedApplication(packageName) } catch (_: Exception) {}

        val pfd = builder.establish()
        if (pfd == null) {
            appendLog("ошибка: система не дала создать VPN-интерфейс (нет разрешения?)")
            state = "off"
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }
        tun = pfd
        appendLog("VPN-интерфейс создан (10.77.0.2/24, DNS 10.77.0.1)")

        Thread {
            try {
                if (!Python.isStarted()) Python.start(AndroidPlatform(this))
                val py = Python.getInstance()
                val mod = py.getModule("spacecop.tun.android")
                // Point ctypes at libspacecop_crypto.so bundled in the APK.
                py.getModule("spacecop.crypto.native").callAttr("set_native_dir", applicationInfo.nativeLibraryDir)
                // Python sockets must be protect()ed: expose a callback the client
                // uses right after creating its UDP socket.
                mod.callAttr("set_socket_protector", SocketProtector(this))
                val h = mod.callAttr("run_engine", pfd.fd, uris.toTypedArray(), dns, discover, PyLogger())
                handle = h
                state = "on"
                val backend = py.getModule("spacecop.crypto.aead").callAttr("backend").toString()
                appendLog("crypto: $backend")
                if (!backend.startsWith("native")) {
                    appendLog(py.getModule("spacecop.crypto.native").callAttr("diagnostics").toString())
                }
                updateNotification("Подключено · узлов: ${uris.size}")
                startPoller(h)
            } catch (e: Exception) {
                Log.e(TAG, "engine failed", e)
                appendLog("ошибка: " + ((e.message ?: "").lines().lastOrNull { it.isNotBlank() } ?: e.toString()))
                stopVpn()
            }
        }.start()
    }

    private fun startPoller(h: PyObject) {
        val t = Thread {
            while (state == "on" && handle === h) {
                try {
                    statusJson = h.callAttr("__getitem__", "status_json").call().toString()
                } catch (_: Exception) {}
                try { Thread.sleep(1000) } catch (_: InterruptedException) { break }
            }
        }
        t.isDaemon = true
        poller = t
        t.start()
    }

    private fun stopVpn() {
        val h = handle
        handle = null
        state = "off"
        poller?.interrupt(); poller = null
        try { h?.callAttr("__getitem__", "stop")?.call() } catch (_: Exception) {}
        try { tun?.close() } catch (_: Exception) {}
        tun = null
        statusJson = ""
        appendLog("VPN остановлен")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() { if (state != "off") stopVpn(); super.onDestroy() }
    override fun onRevoke() { stopVpn(); super.onRevoke() }

    private fun buildNotification(text: String): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL, "SpaceCopVPN", NotificationManager.IMPORTANCE_LOW))
        }
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val b = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            Notification.Builder(this, CHANNEL) else @Suppress("DEPRECATION") Notification.Builder(this)
        return b.setContentTitle("SpaceCopVPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java).notify(1, buildNotification(text))
    }
}

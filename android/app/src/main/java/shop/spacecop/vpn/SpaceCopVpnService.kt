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
import java.io.FileDescriptor

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

        @Volatile var running: Boolean = false
        @Volatile var lastLog: String = ""
    }

    private var tun: ParcelFileDescriptor? = null
    private var handle: PyObject? = null

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
        if (running) return
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

        val pfd = builder.establish() ?: run { stopSelf(); return }
        tun = pfd

        if (!Python.isStarted()) Python.start(AndroidPlatform(this))
        val py = Python.getInstance()

        // Python sockets must be protect()ed: expose a callback the client uses
        // right after creating its UDP socket.
        val protector = object : Any() {
            @Suppress("unused")
            fun protectFd(fd: Int): Boolean = protect(fd)
        }
        py.getModule("spacecop.tun.android").callAttr("set_socket_protector", protector)

        val logger = object : Any() {
            @Suppress("unused")
            fun log(line: String) { lastLog = line; Log.i(TAG, line) }
        }

        Thread {
            try {
                handle = py.getModule("spacecop.tun.android").callAttr(
                    "run_engine", pfd.fd, uris.toTypedArray(), dns, discover, logger
                )
                running = true
                updateNotification("Подключено · ${uris.size} узл.")
            } catch (e: Exception) {
                Log.e(TAG, "engine failed", e)
                lastLog = "ошибка: ${e.message}"
                stopVpn()
            }
        }.start()
    }

    private fun stopVpn() {
        try { handle?.callAttr("__getitem__", "stop")?.call() } catch (_: Exception) {}
        handle = null
        try { tun?.close() } catch (_: Exception) {}
        tun = null
        running = false
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() { stopVpn(); super.onDestroy() }
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
        return Notification.Builder(this, CHANNEL)
            .setContentTitle("SpaceCopVPN")
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

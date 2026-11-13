package com.beamdrop.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat

class BeamDropReceiveService : Service() {
    private var multicastLock: WifiManager.MulticastLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        ensureNotificationChannel()
        acquireMulticastLock()
        isRunning = true
        BeamDropTileService.requestRefresh(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            isRunning = false
            releaseMulticastLock()
            BeamDropTileService.requestRefresh(this)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } else {
                @Suppress("DEPRECATION")
                stopForeground(true)
            }
            stopSelf()
            return START_NOT_STICKY
        }

        acquireMulticastLock()
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        isRunning = true
        BeamDropTileService.requestRefresh(this)
        return START_STICKY
    }

    override fun onDestroy() {
        isRunning = false
        releaseMulticastLock()
        BeamDropTileService.requestRefresh(this)
        super.onDestroy()
    }

    private fun acquireMulticastLock() {
        val lock = multicastLock
        if (lock != null && lock.isHeld) {
            return
        }
        val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager ?: return
        try {
            val created = lock ?: wifi.createMulticastLock("BeamDropMdnsLock").apply {
                setReferenceCounted(false)
            }
            if (!created.isHeld) {
                created.acquire()
            }
            multicastLock = created
        } catch (_: SecurityException) {
            // Ignored if Wi-Fi state permission is revoked.
        }
    }

    private fun releaseMulticastLock() {
        try {
            if (multicastLock?.isHeld == true) {
                multicastLock?.release()
            }
        } catch (_: Exception) {
            // Safe cleanup when lock was already released.
        } finally {
            multicastLock = null
        }
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(NotificationManager::class.java) ?: return
        if (manager.getNotificationChannel(CHANNEL_ID) != null) return

        val channel = NotificationChannel(
            CHANNEL_ID,
            "BeamDrop Background Receiver",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Keeps Wi-Fi mDNS discovery and peer-to-peer transfers ready"
            setShowBadge(false)
        }
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification {
        val launchIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingFlags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        val contentIntent = PendingIntent.getActivity(this, 0, launchIntent, pendingFlags)

        val stopIntent = Intent(this, BeamDropReceiveService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPendingIntent = PendingIntent.getService(this, 1, stopIntent, pendingFlags)

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_qs_beamdrop)
            .setContentTitle("BeamDrop Ready")
            .setContentText("BeamDrop Ready — Listening on Wi-Fi")
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(contentIntent)
            .addAction(0, "Stop", stopPendingIntent)
            .build()
    }

    companion object {
        const val CHANNEL_ID = "beamdrop_receive_channel"
        const val NOTIFICATION_ID = 4107
        const val ACTION_START = "com.beamdrop.app.action.START_RECEIVE"
        const val ACTION_STOP = "com.beamdrop.app.action.STOP_RECEIVE"

        @Volatile
        var isRunning: Boolean = false
            private set

        fun start(context: Context) {
            val intent = Intent(context, BeamDropReceiveService::class.java).apply {
                action = ACTION_START
            }
            ContextCompat.startForegroundService(context, intent)
        }

        fun stop(context: Context) {
            val intent = Intent(context, BeamDropReceiveService::class.java).apply {
                action = ACTION_STOP
            }
            if (isRunning) {
                context.startService(intent)
            } else {
                context.stopService(intent)
            }
        }
    }
}


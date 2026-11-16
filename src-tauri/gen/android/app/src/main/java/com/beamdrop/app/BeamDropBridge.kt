package com.beamdrop.app

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.BitmapFactory
import android.media.AudioAttributes
import android.media.RingtoneManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import android.webkit.MimeTypeMap
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import java.io.File
import java.io.FileOutputStream
import java.util.UUID
import java.util.concurrent.ConcurrentLinkedQueue

object BeamDropBridge {
    const val SHARE_CACHE_SUBDIR = "beamdrop_share"
    private const val COPY_BUFFER_BYTES = 131_072 // 128 KiB streaming copy
    private const val INCOMING_CHANNEL_ID = "zapdrop_incoming_transfers"
    private const val LEGACY_INCOMING_CHANNEL_ID = "beamdrop_incoming_transfer_high"
    private const val INCOMING_NOTIFICATION_ID = 4109
    private const val REQUEST_CODE_ACCEPT = 4110
    private const val REQUEST_CODE_DECLINE = 4111
    const val ACTION_ACCEPT_TRANSFER = "com.beamdrop.app.ACTION_ACCEPT_INCOMING_TRANSFER"
    const val ACTION_DECLINE_TRANSFER = "com.beamdrop.app.ACTION_DECLINE_INCOMING_TRANSFER"
    const val EXTRA_TRANSFER_ID = "extra_transfer_id"
    const val EXTRA_ACCEPT_TRANSFER = "extra_accept_transfer"

    private data class TargetedShareBatch(
        val targetNodeId: String,
        val paths: List<String>
    )

    @Volatile
    private var rustReady = false
    private val bufferedPaths = ConcurrentLinkedQueue<String>()
    private val bufferedTargeted = ConcurrentLinkedQueue<TargetedShareBatch>()
    private val bufferedPairingUris = ConcurrentLinkedQueue<String>()

    /**
     * Invoked from Rust once `AppState` and `ANDROID_APP_HANDLE` are initialized.
     * Flushes any shares or `beamdrop://pair?...` deep links buffered during cold start.
     */
    @JvmStatic
    fun drainPendingToNative() {
        rustReady = true
        flushBufferedPaths()
        flushBufferedTargeted()
        flushBufferedPairingUris()
    }

    fun enqueuePaths(paths: List<String>) {
        val clean = paths.filter { it.isNotBlank() }
        if (clean.isEmpty()) return

        if (rustReady) {
            flushAndQueuePaths(clean)
        } else {
            bufferedPaths.addAll(clean)
            if (rustReady) {
                flushBufferedPaths()
            }
        }
    }

    fun enqueueTargetedSend(targetNodeId: String, paths: List<String>) {
        val trimmedTarget = targetNodeId.trim()
        val clean = paths.filter { it.isNotBlank() }
        if (trimmedTarget.isEmpty() || clean.isEmpty()) return

        if (rustReady) {
            try {
                nativeQueueTargetedSend(trimmedTarget, clean.toTypedArray())
            } catch (_: UnsatisfiedLinkError) {
                bufferedTargeted.add(TargetedShareBatch(trimmedTarget, clean))
            }
        } else {
            bufferedTargeted.add(TargetedShareBatch(trimmedTarget, clean))
            if (rustReady) {
                flushBufferedTargeted()
            }
        }
    }

    @JvmStatic
    fun enqueuePairingUri(rawUri: String?) {
        val clean = rawUri?.trim().orEmpty()
        if (!clean.startsWith("beamdrop://", ignoreCase = true)) return

        if (rustReady) {
            try {
                nativeQueuePairingUri(clean)
            } catch (_: UnsatisfiedLinkError) {
                bufferedPairingUris.add(clean)
            }
        } else {
            bufferedPairingUris.add(clean)
            if (rustReady) {
                flushBufferedPairingUris()
            }
        }
    }

    /**
     * Resolves Android `content://` or `file://` URIs into readable POSIX file paths
     * inside `cacheDir/beamdrop_share/`, streaming in 128 KiB chunks.
     */
    @JvmStatic
    fun resolveContentUris(context: Context, rawUris: Array<String>): Array<String> {
        val resolvedPaths = mutableListOf<String>()
        var batchDir: File? = null
        val buffer = ByteArray(COPY_BUFFER_BYTES)

        for ((index, raw) in rawUris.withIndex()) {
            val trimmed = raw.trim()
            if (trimmed.isEmpty()) continue

            if (trimmed.startsWith("/")) {
                val direct = File(trimmed)
                if (direct.exists()) {
                    resolvedPaths.add(direct.absolutePath)
                    continue
                }
            }

            val uri = Uri.parse(trimmed)
            if ("file".equals(uri.scheme, ignoreCase = true)) {
                val directPath = uri.path
                if (!directPath.isNullOrBlank()) {
                    val directFile = File(directPath)
                    if (directFile.exists()) {
                        resolvedPaths.add(directFile.absolutePath)
                        continue
                    }
                }
            }

            val targetDir = batchDir ?: File(
                File(context.cacheDir, SHARE_CACHE_SUBDIR),
                UUID.randomUUID().toString()
            ).also {
                if (!it.exists()) {
                    it.mkdirs()
                }
                batchDir = it
            }

            val rawName = queryDisplayName(context, uri) ?: fallbackFileName(context, uri, index)
            val safeName = sanitizeFileName(rawName, "shared_item_${index + 1}")
            val destFile = resolveUniqueFile(targetDir, safeName)

            val copied = try {
                context.contentResolver.openInputStream(uri)?.use { input ->
                    FileOutputStream(destFile).use { output ->
                        while (true) {
                            val read = input.read(buffer)
                            if (read <= 0) break
                            output.write(buffer, 0, read)
                        }
                        output.flush()
                    }
                    true
                } ?: false
            } catch (_: Exception) {
                destFile.delete()
                false
            }

            if (copied && destFile.isFile) {
                resolvedPaths.add(destFile.absolutePath)
            }
        }

        return resolvedPaths.toTypedArray()
    }

    private fun queryDisplayName(context: Context, uri: Uri): String? {
        if ("file".equals(uri.scheme, ignoreCase = true)) {
            return uri.lastPathSegment
        }
        return try {
            context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
                ?.use { cursor ->
                    if (cursor.moveToFirst()) {
                        val col = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                        if (col >= 0) cursor.getString(col) else null
                    } else {
                        null
                    }
                }
        } catch (_: Exception) {
            null
        }
    }

    private fun fallbackFileName(context: Context, uri: Uri, index: Int): String {
        val mime = try {
            context.contentResolver.getType(uri)
        } catch (_: Exception) {
            null
        }
        val ext = if (!mime.isNullOrBlank()) {
            MimeTypeMap.getSingleton().getExtensionFromMimeType(mime)
        } else {
            null
        }
        return if (!ext.isNullOrBlank()) {
            "shared_${index + 1}.$ext"
        } else {
            "shared_${index + 1}"
        }
    }

    private fun sanitizeFileName(name: String, fallback: String): String {
        val stripped = name
            .replace('\\', '/')
            .substringAfterLast('/')
            .trim()
            .filter { ch -> ch >= ' ' && ch != '/' && ch != '\\' && ch != '\u0000' }

        if (stripped.isEmpty() || stripped == "." || stripped == "..") {
            return fallback
        }
        return stripped
    }

    private fun resolveUniqueFile(dir: File, name: String): File {
        val first = File(dir, name)
        if (!first.exists()) return first

        val dot = name.lastIndexOf('.')
        val stem = if (dot > 0) name.substring(0, dot) else name
        val ext = if (dot > 0) name.substring(dot) else ""

        for (i in 1..9999) {
            val candidate = File(dir, "$stem ($i)$ext")
            if (!candidate.exists()) return candidate
        }
        return File(dir, "${System.currentTimeMillis()}_$name")
    }

    private inline fun <T> drainQueue(queue: ConcurrentLinkedQueue<T>): List<T> {
        val items = mutableListOf<T>()
        while (true) {
            val item = queue.poll() ?: break
            items.add(item)
        }
        return items
    }

    private fun flushBufferedPaths() {
        val drained = drainQueue(bufferedPaths)
        if (drained.isEmpty()) return

        try {
            nativeQueueSharedPaths(drained.toTypedArray())
        } catch (_: UnsatisfiedLinkError) {
            bufferedPaths.addAll(drained)
        }
    }

    private fun flushBufferedTargeted() {
        val pending = drainQueue(bufferedTargeted)
        if (pending.isEmpty()) return

        for (batch in pending) {
            try {
                nativeQueueTargetedSend(batch.targetNodeId, batch.paths.toTypedArray())
            } catch (_: UnsatisfiedLinkError) {
                bufferedTargeted.add(batch)
            }
        }
    }

    private fun flushBufferedPairingUris() {
        val pending = drainQueue(bufferedPairingUris)
        if (pending.isEmpty()) return

        for (uri in pending) {
            try {
                nativeQueuePairingUri(uri)
            } catch (_: UnsatisfiedLinkError) {
                bufferedPairingUris.add(uri)
            }
        }
    }

    private fun flushAndQueuePaths(paths: List<String>) {
        val combined = drainQueue(bufferedPaths).toMutableList()
        combined.addAll(paths)
        try {
            nativeQueueSharedPaths(combined.toTypedArray())
        } catch (_: UnsatisfiedLinkError) {
            bufferedPaths.addAll(combined)
        }
    }

    @JvmStatic
    fun isOnMeteredCellular(context: Context): Boolean {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return false
        val activeNetwork = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(activeNetwork) ?: return false
        val isCellular = caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
        val isNotMetered = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
        return isCellular && (!isNotMetered || cm.isActiveNetworkMetered)
    }

    @JvmStatic
    fun showIncomingTransferNotification(
        context: Context,
        transferId: String,
        title: String,
        body: String
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                return
            }
        }

        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            try {
                manager.deleteNotificationChannel(LEGACY_INCOMING_CHANNEL_ID)
            } catch (_: Exception) {
                // Ignore if legacy channel was never created.
            }
            val existing = manager.getNotificationChannel(INCOMING_CHANNEL_ID)
            if (existing == null || existing.importance < NotificationManager.IMPORTANCE_HIGH) {
                val channel = NotificationChannel(
                    INCOMING_CHANNEL_ID,
                    "Incoming Transfer Requests",
                    NotificationManager.IMPORTANCE_HIGH
                ).apply {
                    description = "High-priority alerts when a peer asks to send files"
                    enableVibration(true)
                    setSound(
                        RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION),
                        AudioAttributes.Builder()
                            .setUsage(AudioAttributes.USAGE_NOTIFICATION)
                            .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                            .build()
                    )
                    setShowBadge(true)
                }
                manager.createNotificationChannel(channel)
            }
        }

        val launchIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_NEW_TASK
        }
        val pendingFlags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        val contentIntent = PendingIntent.getActivity(context, 41, launchIntent, pendingFlags)

        val acceptIntent = Intent(context, IncomingTransferActionReceiver::class.java).apply {
            action = ACTION_ACCEPT_TRANSFER
            putExtra(EXTRA_TRANSFER_ID, transferId)
            putExtra(EXTRA_ACCEPT_TRANSFER, true)
        }
        val declineIntent = Intent(context, IncomingTransferActionReceiver::class.java).apply {
            action = ACTION_DECLINE_TRANSFER
            putExtra(EXTRA_TRANSFER_ID, transferId)
            putExtra(EXTRA_ACCEPT_TRANSFER, false)
        }
        val actionFlags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        val acceptPendingIntent = PendingIntent.getBroadcast(
            context,
            REQUEST_CODE_ACCEPT,
            acceptIntent,
            actionFlags
        )
        val declinePendingIntent = PendingIntent.getBroadcast(
            context,
            REQUEST_CODE_DECLINE,
            declineIntent,
            actionFlags
        )
        val largeIcon = BitmapFactory.decodeResource(context.resources, R.mipmap.ic_launcher)

        val notification = NotificationCompat.Builder(context, INCOMING_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_qs_beamdrop)
            .apply {
                if (largeIcon != null) {
                    setLargeIcon(largeIcon)
                }
            }
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setDefaults(NotificationCompat.DEFAULT_ALL)
            .setAutoCancel(true)
            .setTimeoutAfter(60_000L)
            .setContentIntent(contentIntent)
            .addAction(0, "Accept", acceptPendingIntent)
            .addAction(0, "Decline", declinePendingIntent)
            .build()

        try {
            manager.notify(INCOMING_NOTIFICATION_ID, notification)
        } catch (_: SecurityException) {
            // Permission revoked mid-flight.
        }
    }

    @JvmStatic
    fun dismissIncomingTransferNotification(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        manager.cancel(INCOMING_NOTIFICATION_ID)
    }

    @JvmStatic
    external fun nativeQueueSharedPaths(paths: Array<String>)

    @JvmStatic
    external fun nativeQueueTargetedSend(targetNodeId: String, paths: Array<String>)

    @JvmStatic
    fun respondFromNotification(transferId: String, accept: Boolean) {
        if (transferId.isBlank() || !rustReady) return
        try {
            nativeRespondToOffer(transferId, accept)
        } catch (_: UnsatisfiedLinkError) {
            // Native library not initialized yet.
        }
    }

    @JvmStatic
    external fun nativeQueuePairingUri(uri: String)

    @JvmStatic
    external fun nativeRespondToOffer(transferId: String, accept: Boolean)

    @JvmStatic
    external fun nativeGetTrustedPeersJson(): String
}

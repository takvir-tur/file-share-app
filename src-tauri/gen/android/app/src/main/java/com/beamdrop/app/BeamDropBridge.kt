package com.beamdrop.app

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.provider.OpenableColumns
import android.webkit.MimeTypeMap
import java.io.File
import java.io.FileOutputStream
import java.util.UUID
import java.util.concurrent.ConcurrentLinkedQueue

object BeamDropBridge {
    const val SHARE_CACHE_SUBDIR = "beamdrop_share"
    private const val COPY_BUFFER_BYTES = 131_072 // 128 KiB streaming copy

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
    external fun nativeQueueSharedPaths(paths: Array<String>)

    @JvmStatic
    external fun nativeQueueTargetedSend(targetNodeId: String, paths: Array<String>)

    @JvmStatic
    external fun nativeQueuePairingUri(uri: String)

    @JvmStatic
    external fun nativeGetTrustedPeersJson(): String
}

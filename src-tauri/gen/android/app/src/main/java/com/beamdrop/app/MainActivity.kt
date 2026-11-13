package com.beamdrop.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import android.provider.Settings
import android.system.Os
import android.webkit.MimeTypeMap
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.core.content.IntentCompat
import java.io.File
import java.io.FileOutputStream
import java.util.UUID
import java.util.concurrent.Executors

class MainActivity : TauriActivity() {
    private val shareExecutor = Executors.newSingleThreadExecutor()

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { _ ->
        // Foreground service continues running with or without notification visibility.
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        setFriendlyHostnameEnv()
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)

        BeamDropBridge.markNativeReady()
        ensureReceiveServiceStarted()
        cleanupStaleShareCache()
        handleShareIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleShareIntent(intent)
    }

    override fun onDestroy() {
        shareExecutor.shutdown()
        super.onDestroy()
    }

    private fun setFriendlyHostnameEnv() {
        val friendlyName = resolveFriendlyDeviceName()
        try {
            Os.setenv("BEAMDROP_HOSTNAME", friendlyName, true)
        } catch (_: Exception) {
        }
    }

    private fun resolveFriendlyDeviceName(): String {
        val customName = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N_MR1) {
                Settings.Global.getString(contentResolver, Settings.Global.DEVICE_NAME)
            } else {
                null
            }
        } catch (_: Exception) {
            null
        }?.trim()

        if (!customName.isNullOrEmpty() && !customName.equals("localhost", ignoreCase = true)) {
            return customName
        }

        val manufacturer = Build.MANUFACTURER?.trim().orEmpty()
        val model = Build.MODEL?.trim().orEmpty()
        return when {
            model.isNotEmpty() &&
                manufacturer.isNotEmpty() &&
                !model.startsWith(manufacturer, ignoreCase = true) -> {
                val brand = manufacturer.replaceFirstChar { it.uppercase() }
                "$brand $model"
            }
            model.isNotEmpty() -> model
            manufacturer.isNotEmpty() -> manufacturer.replaceFirstChar { it.uppercase() }
            else -> "Android Device"
        }
    }

    private fun ensureReceiveServiceStarted() {
        try {
            BeamDropReceiveService.start(this)
        } catch (_: Exception) {
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    private fun handleShareIntent(incoming: Intent?) {
        val intent = incoming ?: return
        val action = intent.action ?: return
        if (action != Intent.ACTION_SEND && action != Intent.ACTION_SEND_MULTIPLE) {
            return
        }

        val uris = collectSharedUris(intent)
        if (uris.isEmpty()) return

        shareExecutor.execute {
            val copiedPaths = copySharedUrisToCache(uris)
            if (copiedPaths.isNotEmpty()) {
                BeamDropBridge.enqueuePaths(copiedPaths)
            }
        }
    }

    private fun collectSharedUris(intent: Intent): List<Uri> {
        val ordered = LinkedHashSet<Uri>()

        when (intent.action) {
            Intent.ACTION_SEND -> {
                IntentCompat.getParcelableExtra(intent, Intent.EXTRA_STREAM, Uri::class.java)
                    ?.let { ordered.add(it) }
            }
            Intent.ACTION_SEND_MULTIPLE -> {
                IntentCompat.getParcelableArrayListExtra(intent, Intent.EXTRA_STREAM, Uri::class.java)
                    ?.forEach { ordered.add(it) }
            }
        }

        val clip = intent.clipData
        if (clip != null) {
            for (i in 0 until clip.itemCount) {
                clip.getItemAt(i)?.uri?.let { ordered.add(it) }
            }
        }

        return ordered.toList()
    }

    private fun copySharedUrisToCache(uris: List<Uri>): List<String> {
        val batchDir = File(File(cacheDir, SHARE_CACHE_SUBDIR), UUID.randomUUID().toString())
        if (!batchDir.exists() && !batchDir.mkdirs()) {
            return emptyList()
        }

        val resolvedPaths = mutableListOf<String>()
        val buffer = ByteArray(COPY_BUFFER_BYTES)

        for ((index, uri) in uris.withIndex()) {
            val rawName = queryDisplayName(uri) ?: fallbackFileName(uri, index)
            val safeName = sanitizeFileName(rawName, "shared_item_${index + 1}")
            val destFile = resolveUniqueFile(batchDir, safeName)

            val copied = try {
                contentResolver.openInputStream(uri)?.use { input ->
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

        return resolvedPaths
    }

    private fun queryDisplayName(uri: Uri): String? {
        if ("file".equals(uri.scheme, ignoreCase = true)) {
            return uri.lastPathSegment
        }
        return try {
            contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
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

    private fun fallbackFileName(uri: Uri, index: Int): String {
        val mime = try {
            contentResolver.getType(uri)
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

    private fun cleanupStaleShareCache() {
        shareExecutor.execute {
            val shareRoot = File(cacheDir, SHARE_CACHE_SUBDIR)
            if (!shareRoot.isDirectory) return@execute
            val cutoffMs = System.currentTimeMillis() - SHARE_CACHE_TTL_MS
            shareRoot.listFiles()?.forEach { child ->
                if (child.lastModified() < cutoffMs) {
                    child.deleteRecursively()
                }
            }
        }
    }

    companion object {
        private const val SHARE_CACHE_SUBDIR = "beamdrop_share"
        private const val COPY_BUFFER_BYTES = 131_072 // 128 KiB streaming copy
        private const val SHARE_CACHE_TTL_MS = 24L * 60L * 60L * 1000L
    }
}

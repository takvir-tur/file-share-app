package com.beamdrop.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.system.Os
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.core.content.IntentCompat
import androidx.core.content.pm.ShortcutManagerCompat
import java.io.File
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

        ensureReceiveServiceStarted()
        BeamDropShortcuts.syncShortcuts(this)
        cleanupStaleShareCache()
        handleIncomingIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIncomingIntent(intent)
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

    private fun handleIncomingIntent(incoming: Intent?) {
        val intent = incoming ?: return
        val action = intent.action ?: return

        if (action == Intent.ACTION_VIEW) {
            val uriStr = intent.dataString ?: intent.data?.toString()
            if (!uriStr.isNullOrBlank() && uriStr.startsWith("beamdrop://", ignoreCase = true)) {
                BeamDropBridge.enqueuePairingUri(uriStr)
            }
            return
        }

        if (action != Intent.ACTION_SEND && action != Intent.ACTION_SEND_MULTIPLE) {
            return
        }

        val uris = collectSharedUris(intent)
        if (uris.isEmpty()) return

        val shortcutId = intent.getStringExtra(ShortcutManagerCompat.EXTRA_SHORTCUT_ID)
            ?: if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                intent.getStringExtra(Intent.EXTRA_SHORTCUT_ID)
            } else {
                null
            }
        val targetNodeId = shortcutId
            ?.takeIf { it.startsWith(BeamDropShortcuts.SHORTCUT_ID_PREFIX) }
            ?.removePrefix(BeamDropShortcuts.SHORTCUT_ID_PREFIX)
            ?.trim()
            ?.takeIf { it.isNotEmpty() }

        val rawUris = uris.map { it.toString() }.toTypedArray()
        shareExecutor.execute {
            val copiedPaths = BeamDropBridge.resolveContentUris(this, rawUris).toList()
            if (copiedPaths.isNotEmpty()) {
                if (targetNodeId != null) {
                    BeamDropBridge.enqueueTargetedSend(targetNodeId, copiedPaths)
                } else {
                    BeamDropBridge.enqueuePaths(copiedPaths)
                }
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

    private fun cleanupStaleShareCache() {
        shareExecutor.execute {
            val shareRoot = File(cacheDir, BeamDropBridge.SHARE_CACHE_SUBDIR)
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
        private const val SHARE_CACHE_TTL_MS = 24L * 60L * 60L * 1000L
    }
}

package com.beamdrop.app

import android.content.Context
import android.content.Intent
import androidx.core.app.Person
import androidx.core.content.pm.ShortcutInfoCompat
import androidx.core.content.pm.ShortcutManagerCompat
import androidx.core.graphics.drawable.IconCompat
import org.json.JSONArray
import java.util.concurrent.Executors

object BeamDropShortcuts {
    const val SHORTCUT_ID_PREFIX = "peer_"
    const val SHARE_CATEGORY = "com.beamdrop.app.category.DIRECT_SHARE"

    private val syncExecutor = Executors.newSingleThreadExecutor()

    @JvmStatic
    fun syncShortcuts(context: Context) {
        val appContext = context.applicationContext
        syncExecutor.execute {
            syncShortcutsBlocking(appContext)
        }
    }

    private fun syncShortcutsBlocking(appContext: Context) {
        val json = try {
            BeamDropBridge.nativeGetTrustedPeersJson()
        } catch (_: UnsatisfiedLinkError) {
            return
        } catch (_: Exception) {
            return
        }

        val parsed = try {
            JSONArray(json)
        } catch (_: Exception) {
            return
        }

        val maxShortcuts = ShortcutManagerCompat.getMaxShortcutCountPerActivity(appContext)
            .coerceAtLeast(1)
        val shortcuts = mutableListOf<ShortcutInfoCompat>()

        for (i in 0 until parsed.length()) {
            if (shortcuts.size >= maxShortcuts) break
            val item = parsed.optJSONObject(i) ?: continue
            val nodeId = item.optString("node_id", "").trim()
            if (nodeId.isEmpty()) continue

            val alias = item.optString("friendly_alias", "").trim().ifEmpty {
                "Device ${nodeId.take(6)}"
            }
            val osType = item.optString("os_type", "").trim()

            val targetIntent = Intent(appContext, MainActivity::class.java).apply {
                action = Intent.ACTION_SEND
            }

            val person = Person.Builder()
                .setName(alias)
                .setKey(nodeId)
                .build()

            val shortcut = ShortcutInfoCompat.Builder(appContext, "$SHORTCUT_ID_PREFIX$nodeId")
                .setShortLabel(alias)
                .setLongLabel(alias)
                .setIcon(IconCompat.createWithResource(appContext, iconResForOs(osType)))
                .setLongLived(true)
                .setPerson(person)
                .setCategories(setOf(SHARE_CATEGORY))
                .setIntent(targetIntent)
                .build()

            shortcuts.add(shortcut)
        }

        try {
            ShortcutManagerCompat.removeAllDynamicShortcuts(appContext)
            if (shortcuts.isNotEmpty()) {
                ShortcutManagerCompat.addDynamicShortcuts(appContext, shortcuts)
            }
        } catch (_: Exception) {
        }
    }

    private fun iconResForOs(osType: String): Int {
        return when (osType.lowercase()) {
            "macos" -> R.drawable.ic_peer_macos
            "windows" -> R.drawable.ic_peer_windows
            "android" -> R.drawable.ic_peer_android
            else -> R.drawable.ic_peer_generic
        }
    }
}


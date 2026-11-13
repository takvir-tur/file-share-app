package com.beamdrop.app

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

class BeamDropTileService : TileService() {

    override fun onTileAdded() {
        super.onTileAdded()
        syncTileState(BeamDropReceiveService.isRunning)
    }

    override fun onStartListening() {
        super.onStartListening()
        syncTileState(BeamDropReceiveService.isRunning)
    }

    override fun onClick() {
        super.onClick()
        val currentlyActive = BeamDropReceiveService.isRunning
        if (currentlyActive) {
            BeamDropReceiveService.stop(this)
            syncTileState(false)
            return
        }

        try {
            BeamDropReceiveService.start(this)
            syncTileState(true)
        } catch (_: Exception) {
            val launchIntent = Intent(this, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                val pending = PendingIntent.getActivity(
                    this,
                    0,
                    launchIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )
                startActivityAndCollapse(pending)
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(launchIntent)
            }
        }
    }

    private fun syncTileState(active: Boolean) {
        val tile = qsTile ?: return
        tile.label = getString(R.string.qs_tile_label)
        tile.state = if (active) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = if (active) "Listening on Wi-Fi" else "Off"
        }
        tile.updateTile()
    }

    companion object {
        fun requestRefresh(context: Context) {
            try {
                requestListeningState(
                    context.applicationContext,
                    ComponentName(context.applicationContext, BeamDropTileService::class.java)
                )
            } catch (_: Exception) {
                // Tile may not be pinned on the user's Quick Settings panel.
            }
        }
    }
}

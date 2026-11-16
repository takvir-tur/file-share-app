package com.beamdrop.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class IncomingTransferActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent == null) return

        val action = intent.action
        val accept = when (action) {
            BeamDropBridge.ACTION_ACCEPT_TRANSFER -> true
            BeamDropBridge.ACTION_DECLINE_TRANSFER -> false
            else -> intent.getBooleanExtra(BeamDropBridge.EXTRA_ACCEPT_TRANSFER, false)
        }
        val transferId = intent.getStringExtra(BeamDropBridge.EXTRA_TRANSFER_ID)?.trim().orEmpty()

        BeamDropBridge.dismissIncomingTransferNotification(context)

        if (transferId.isNotEmpty()) {
            BeamDropBridge.respondFromNotification(transferId, accept)
        }
    }
}

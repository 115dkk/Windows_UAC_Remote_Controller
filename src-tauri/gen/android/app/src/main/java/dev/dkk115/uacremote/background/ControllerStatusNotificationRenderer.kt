// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.os.Build
import dev.dkk115.uacremote.R
import dev.dkk115.uacremote.AppLanguage

/** Existing status presentation only. Caller owns the real state, open intent,
 * notification posting and foreground lifetime; this class starts no owner. */
internal class ControllerStatusNotificationRenderer(private val source: Context) {
    private val context: Context get() = AppLanguage.context(source)
    fun ensureChannel() {
        val manager = context.getSystemService(NotificationManager::class.java) ?: throw IllegalStateException()
        val channel = NotificationChannel(CHANNEL_ID, context.getString(R.string.controller_service_channel), NotificationManager.IMPORTANCE_LOW)
        channel.description = context.getString(R.string.controller_service_channel_description)
        channel.setSound(null, null)
        channel.enableVibration(false)
        channel.setShowBadge(false)
        manager.createNotificationChannel(channel)
    }

    fun build(state: ControllerServiceState, open: PendingIntent): Notification {
        val context = this.context
        val body = when (state) {
            ControllerServiceState.WAITING_FOR_UNLOCK -> R.string.controller_service_locked
            ControllerServiceState.PREPARING -> R.string.controller_service_preparing
            ControllerServiceState.LOCAL_SETTINGS_READY -> R.string.controller_service_ready
            ControllerServiceState.CLEANUP_PENDING -> R.string.controller_service_cleanup
            ControllerServiceState.UNAVAILABLE -> R.string.controller_service_unavailable
            ControllerServiceState.STOPPED -> R.string.controller_service_stopping
        }
        val builder = Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_controller_service)
            .setContentTitle(context.getString(R.string.controller_service_title))
            .setContentText(context.getString(body))
            .setContentIntent(open)
            .setCategory(Notification.CATEGORY_SERVICE)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setLocalOnly(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) builder.setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE)
        return builder.build()
    }

    companion object {
        const val CHANNEL_ID = "controller_service_status_v1"
        const val NOTIFICATION_ID = 0x554143
    }
}

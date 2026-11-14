// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import dev.dkk115.uacremote.AppLanguage
import dev.dkk115.uacremote.MainActivity
import dev.dkk115.uacremote.R

/** One attempt per waiting episode, including permission-denied or dismissed notices. */
internal class ParkedPromptNotificationState {
    private var waiting = false
    fun observe(count: Int, connected: Boolean): Boolean {
        val next = connected && count in 1..16
        val fresh = next && !waiting
        waiting = next
        return fresh
    }
    fun clear() { waiting = false }
}

/** Display only. The sole intent opens the app without a request selector or action. */
internal class ParkedPromptNotificationRenderer(context: Context) {
    private val source = context.applicationContext
    private val state = ParkedPromptNotificationState()
    private val context: Context get() = AppLanguage.context(source)
    private fun manager(): NotificationManager = source.getSystemService(NotificationManager::class.java)
        ?: throw IllegalStateException("Notification service unavailable")

    @Synchronized fun update(count: Int, connected: Boolean, active: () -> Boolean) {
        // Stop may race a catalogue read. Its cleanup takes this same monitor,
        // so an admitted post is always followed by cancellation, never vice versa.
        if (!active() || !connected || count !in 1..16) { clear(); return }
        if (!state.observe(count, connected)) return
        val context = this.context
        if (Build.VERSION.SDK_INT >= 33 && source.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        val manager = manager()
        if (!manager.areNotificationsEnabled()) return
        val channel = manager.getNotificationChannel(CHANNEL_ID)
            ?: NotificationChannel(CHANNEL_ID, context.getString(R.string.parked_prompt_channel), NotificationManager.IMPORTANCE_DEFAULT)
        // Retain any user-selected importance, sound and vibration settings.
        channel.name = context.getString(R.string.parked_prompt_channel)
        channel.description = context.getString(R.string.parked_prompt_channel_description)
        manager.createNotificationChannel(channel)
        if (channel.importance == NotificationManager.IMPORTANCE_NONE) return
        val open = Intent(context, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        val pending = PendingIntent.getActivity(context, NOTIFICATION_ID, open,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val body = context.getString(R.string.parked_prompt_notification_body)
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_request_notice)
            .setContentTitle(context.getString(R.string.parked_prompt_notification_title))
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setContentIntent(pending)
            .setCategory(NotificationCompat.CATEGORY_EVENT)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setOnlyAlertOnce(true).setAutoCancel(true).setLocalOnly(true).setShowWhen(false)
            .build()
        try { manager.notify(NOTIFICATION_ID, notification) }
        catch (_: SecurityException) { /* Permission may be revoked after the check. */ }
    }

    @Synchronized fun clear() {
        manager().cancel(NOTIFICATION_ID)
        state.clear()
    }

    companion object {
        const val CHANNEL_ID = "uac_parked_prompts_v1"
        const val NOTIFICATION_ID = 0x554144
    }
}

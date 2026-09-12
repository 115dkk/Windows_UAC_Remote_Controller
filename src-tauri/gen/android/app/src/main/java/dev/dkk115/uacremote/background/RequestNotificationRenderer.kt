// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.media.AudioAttributes
import android.media.RingtoneManager
import android.text.BidiFormatter
import android.text.TextDirectionHeuristics
import androidx.core.app.NotificationCompat
import dev.dkk115.uacremote.R
import dev.dkk115.uacremote.AppLanguage

/** Plain bounded display DTO for the real renderer and isolated synthetic CI.
 * Production constructs it ONLY after the original opaque Rust handle check. */
internal class RequestNotificationContent(val program: String, val path: String) {
    init { require(program.isNotEmpty() && program.length <= 512 && path.isNotEmpty() && path.length <= 1024) }
    override fun toString(): String = "RequestNotificationContent([redacted])"
}
internal enum class RequestNotificationMode { SOUND, VIBRATION_ONLY, SILENT }
internal class RequestNotificationActions(val open: PendingIntent, val approve: PendingIntent, val deny: PendingIntent, val details: PendingIntent)
internal object RequestNotificationPolicy {
    fun quiet(fresh: Boolean, previouslyAttempted: Boolean): Boolean = !fresh || previouslyAttempted
    fun silent(quiet: Boolean, mode: RequestNotificationMode): Boolean = quiet || mode == RequestNotificationMode.SILENT
}

/** Framework templates own geometry/semantics. No key/auth, full commands,
 * full-screen intent, custom RemoteViews, native owner or source fixtures. */
internal class RequestNotificationRenderer(context: Context) {
    private val source = context.applicationContext
    private val context: Context get() = AppLanguage.context(source)
    private fun manager(): NotificationManager = context.getSystemService(NotificationManager::class.java)
        ?: throw IllegalStateException("Notification service unavailable")

    fun ensureChannels() {
        val manager = manager()
        for (mode in RequestNotificationMode.values()) {
            val id = channel(mode)
            val name = when (mode) {
                RequestNotificationMode.SOUND -> R.string.request_channel_sound
                RequestNotificationMode.VIBRATION_ONLY -> R.string.request_channel_vibration
                RequestNotificationMode.SILENT -> R.string.request_channel_silent
            }
            val importance = if (mode == RequestNotificationMode.SILENT) NotificationManager.IMPORTANCE_LOW else NotificationManager.IMPORTANCE_HIGH
            val existing = manager.getNotificationChannel(id)
            if (existing != null) {
                // Rename only: preserve the user's importance/sound/vibration.
                existing.name = context.getString(name)
                existing.description = context.getString(R.string.request_channel_description)
                manager.createNotificationChannel(existing)
                continue
            }
            val created = NotificationChannel(id, context.getString(name), importance)
            created.description = context.getString(R.string.request_channel_description)
            created.enableVibration(mode == RequestNotificationMode.VIBRATION_ONLY)
            if (mode == RequestNotificationMode.SOUND) {
                created.setSound(RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION),
                    AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_NOTIFICATION).build())
            } else created.setSound(null, null)
            created.lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            manager.createNotificationChannel(created)
        }
    }

    fun channelEnabled(mode: RequestNotificationMode): Boolean =
        manager().getNotificationChannel(channel(mode))?.importance?.let { it != NotificationManager.IMPORTANCE_NONE } == true

    fun build(content: RequestNotificationContent, mode: RequestNotificationMode, quiet: Boolean, remainingMillis: Long,
              actions: RequestNotificationActions): Notification {
        require(remainingMillis in 1..300_000L)
        val context = this.context // One locale snapshot for this notification.
        val bidi = BidiFormatter.getInstance(context.resources.configuration.locales[0])
        val program = bidi.unicodeWrap(UntrustedDisplayText.escape(content.program), TextDirectionHeuristics.FIRSTSTRONG_LTR)
        val path = bidi.unicodeWrap(UntrustedDisplayText.escape(content.path), TextDirectionHeuristics.LTR)
        val summary = context.getString(R.string.request_notification_summary, program, path)
        val fits = UntrustedDisplayText.fitsNotification(summary)
        val shown = if (fits) summary else context.getString(R.string.request_notification_public_body)
        val publicVersion = NotificationCompat.Builder(context, channel(mode))
            .setSmallIcon(R.drawable.ic_request_notice)
            .setContentTitle(context.getString(R.string.request_notification_title))
            .setContentText(context.getString(R.string.request_notification_public_body))
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setSilent(true).build()
        val builder = NotificationCompat.Builder(context, channel(mode))
            .setSmallIcon(R.drawable.ic_request_notice)
            .setColor(context.getColor(R.color.request_notification_accent))
            .setContentTitle(context.getString(R.string.request_notification_title))
            .setSubText(context.getString(R.string.request_computer_context))
            .setContentText(if (fits) program else shown)
            .setStyle(NotificationCompat.BigTextStyle().bigText(shown))
            .setContentIntent(actions.open)
            .setCategory(NotificationCompat.CATEGORY_EVENT)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE).setPublicVersion(publicVersion)
            .setOnlyAlertOnce(true).setSilent(RequestNotificationPolicy.silent(quiet, mode))
            .setTimeoutAfter(remainingMillis).setAutoCancel(false).setLocalOnly(true).setShowWhen(false)
        // Do not invite approval from a platform-truncated security identifier.
        // The app details screen owns the full escaped display of long fields.
        if (fits) builder.addAction(R.drawable.ic_request_approve, context.getString(R.string.request_action_approve), actions.approve)
        return builder
            .addAction(R.drawable.ic_request_deny, context.getString(R.string.request_action_deny), actions.deny)
            .addAction(R.drawable.ic_request_details, context.getString(R.string.request_action_details), actions.details)
            .build()
    }

    fun post(tag: String, notification: Notification) { manager().notify(tag, NOTIFICATION_ID, notification) }
    fun withdraw(tag: String) { manager().cancel(tag, NOTIFICATION_ID) }
    fun clearOwned() {
        val manager = manager()
        for (item in manager.activeNotifications) {
            if (item.packageName == context.packageName && item.tag?.startsWith("request:") == true && ownsChannel(item.notification.channelId)) {
                manager.cancel(item.tag, item.id)
            }
        }
    }

    companion object {
        const val NOTIFICATION_ID = 1
        private const val SOUND = "uac_requests_sound_v1"
        private const val VIBRATION = "uac_requests_vibration_v1"
        private const val SILENT = "uac_requests_silent_v1"
        fun channel(mode: RequestNotificationMode): String = when (mode) {
            RequestNotificationMode.SOUND -> SOUND
            RequestNotificationMode.VIBRATION_ONLY -> VIBRATION
            RequestNotificationMode.SILENT -> SILENT
        }
        fun ownsChannel(value: String?): Boolean = value in setOf(SOUND, VIBRATION, SILENT, "uac_requests")
    }
}

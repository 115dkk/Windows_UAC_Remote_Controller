// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.app.Activity
import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Build
import android.os.Process
import android.os.SystemClock
import android.widget.TextView
import org.json.JSONArray
import org.json.JSONObject

/** Isolated CI-only APK. No native owner, Rust/JNA library, network, signing,
 * credential, service, boot receiver or production action handler is linked. */
class GalleryActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        trace("create")
        setContentView(TextView(this).apply {
            text = "알림 화면 예시 · 실제 요청 아님\n\n이 앱은 알림 모양만 확인합니다."
            textSize = 20f
            setPadding(32, 80, 32, 32)
        })
        // No per-launch receipt can be replayed from an earlier CI invocation.
        // Dummy notification actions merely reopen the example text above.
        val nonce = intent.getStringExtra("nonce") ?: return
        require(nonce.length == 36 && nonce.all { it in '0'..'9' || it in 'a'..'f' || it == '-' })
        val selected = intent.getStringExtra("case") ?: "sound"
        require(selected in setOf("sound", "vibration", "silent", "restore", "withdrawn",
            "status-preparing", "status-ready", "status-stopping"))
        val renderer = RequestNotificationRenderer(this)
        renderer.ensureChannels()
        val manager = getSystemService(NotificationManager::class.java) ?: throw IllegalStateException()
        trace("clear")
        renderer.clearOwned()
        manager.cancel(ControllerStatusNotificationRenderer.NOTIFICATION_ID)
        var statusObservation: JSONObject? = null
        val mode = when (selected) {
            "vibration" -> RequestNotificationMode.VIBRATION_ONLY
            "silent" -> RequestNotificationMode.SILENT
            else -> RequestNotificationMode.SOUND
        }
        if (selected.startsWith("status-")) {
            statusObservation = postStatus(selected, manager)
            trace("post")
        } else if (selected != "withdrawn") {
            val pending = { action: String ->
                PendingIntent.getActivity(this, 0,
                    Intent(this, GalleryActivity::class.java).setAction("gallery.$action")
                        .setData(Uri.parse("gallery://example/$action")),
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            }
            val notification = renderer.build(
                RequestNotificationContent("PowerShell", "C:\\Program Files\\PowerShell\\7\\pwsh.exe", false, false),
                mode, selected == "restore", 60_000,
                RequestNotificationActions(pending("open"), pending("approve"), pending("deny"), pending("details")),
            )
            check(notification.actions.size == 3)
            check(notification.actions.map { it.title.toString() } == listOf("승인", "거부", "자세히 보기"))
            check(notification.visibility == Notification.VISIBILITY_PRIVATE)
            check(notification.publicVersion.extras.getCharSequence(Notification.EXTRA_TEXT)?.contains("pwsh") != true)
            check(notification.timeoutAfter == 60_000L)
            check(notification.fullScreenIntent == null)
            renderer.post("request:gallery", notification)
            trace("post")
        }
        filesDir.resolve("gallery-result.json").writeText(JSONObject()
            .put("case", selected).put("nonce", nonce).put("scope", "shared-renderer-only; no production owner/authentication")
            .put("sourceReceipt", sourceReceipt())
            .put("statusNotification", statusObservation ?: JSONObject.NULL)
            .put("completed", true).toString())
    }

    /** Ordinary notify only: exercises the shared builder, never startForeground,
     * a real service state transition, boot startup or a production owner. */
    private fun postStatus(selected: String, manager: NotificationManager): JSONObject {
        val state = when (selected) {
            "status-preparing" -> ControllerServiceState.PREPARING
            "status-ready" -> ControllerServiceState.LOCAL_SETTINGS_READY
            "status-stopping" -> ControllerServiceState.STOPPED
            else -> throw IllegalArgumentException()
        }
        val pending = PendingIntent.getActivity(this, ControllerStatusNotificationRenderer.NOTIFICATION_ID,
            Intent(this, GalleryActivity::class.java).setAction("gallery.status")
                .setData(Uri.parse("gallery://example/status")),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val renderer = ControllerStatusNotificationRenderer(this)
        renderer.ensureChannel()
        val notification = renderer.build(state, pending)
        val channel = manager.getNotificationChannel(ControllerStatusNotificationRenderer.CHANNEL_ID)
            ?: throw IllegalStateException()
        val ongoing = (notification.flags and Notification.FLAG_ONGOING_EVENT) != 0
        val onlyAlertOnce = (notification.flags and Notification.FLAG_ONLY_ALERT_ONCE) != 0
        val localOnly = (notification.flags and Notification.FLAG_LOCAL_ONLY) != 0
        val showWhen = notification.extras.getBoolean(Notification.EXTRA_SHOW_WHEN, true)
        check(notification.channelId == ControllerStatusNotificationRenderer.CHANNEL_ID)
        check(notification.category == Notification.CATEGORY_SERVICE && notification.actions.isNullOrEmpty())
        check(notification.contentIntent == pending && notification.fullScreenIntent == null)
        check(ongoing && onlyAlertOnce && localOnly && !showWhen && notification.timeoutAfter == 0L)
        check((notification.flags and Notification.FLAG_FOREGROUND_SERVICE) == 0)
        check(channel.importance == NotificationManager.IMPORTANCE_LOW && channel.sound == null && !channel.shouldVibrate() && !channel.canShowBadge())
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) check(pending.isImmutable)
        manager.notify(ControllerStatusNotificationRenderer.NOTIFICATION_ID, notification)
        return JSONObject().put("state", state.wireValue)
            .put("notificationId", ControllerStatusNotificationRenderer.NOTIFICATION_ID)
            .put("channelId", notification.channelId)
            .put("title", notification.extras.getCharSequence(Notification.EXTRA_TITLE)?.toString())
            .put("body", notification.extras.getCharSequence(Notification.EXTRA_TEXT)?.toString())
            .put("actions", JSONArray()).put("category", notification.category)
            .put("ongoing", ongoing).put("onlyAlertOnce", onlyAlertOnce).put("localOnly", localOnly)
            .put("showWhen", showWhen).put("timeoutAfter", notification.timeoutAfter)
            .put("fullScreen", false).put("foregroundServicePromotionPerformed", false)
            .put("contentIntentImmutable", if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) pending.isImmutable else JSONObject.NULL)
            .put("channel", JSONObject().put("name", channel.name.toString()).put("description", channel.description)
                .put("importance", channel.importance).put("sound", channel.sound != null)
                .put("vibration", channel.shouldVibrate()).put("badge", channel.canShowBadge()))
    }

    /** Actual copied build inputs packaged with this isolated APK, not hashes
     * asserted by its launch Intent or a duplicate notification implementation. */
    private fun sourceReceipt(): JSONObject = assets.open("gallery-source-receipt.json").use { stream ->
        val bytes = ByteArray(65_537)
        var used = 0
        while (used < bytes.size) {
            val count = stream.read(bytes, used, bytes.size - used)
            if (count < 0) break
            check(count > 0)
            used += count
        }
        check(used in 1..65_536)
        JSONObject(String(bytes, 0, used, Charsets.UTF_8)).also {
            check(it.getInt("schema") == 1 && it.getString("scope") == "exact-shared-renderer-inputs")
            // Six exact Kotlin inputs and twenty resources, including every
            // native locale catalog. The ROOT runner also checks ordered hashes.
            check(it.getJSONArray("files").length() == 26)
        }
    }

    // Bounded test-only lifecycle evidence; no body, key or production owner.
    private fun trace(event: String) {
        val file = filesDir.resolve("gallery-trace.json")
        check(!file.exists() || file.length() <= 32_768)
        val rows = if (file.exists()) JSONArray(file.readText()) else JSONArray()
        check(rows.length() < 32)
        rows.put(JSONObject().put("event", event).put("pid", Process.myPid())
            .put("elapsedMillis", SystemClock.elapsedRealtime()).put("wallMillis", System.currentTimeMillis())
            .put("case", intent.getStringExtra("case") ?: JSONObject.NULL)
            .put("nonce", intent.getStringExtra("nonce") ?: JSONObject.NULL)
            .put("action", intent.action ?: JSONObject.NULL))
        file.writeText(rows.toString())
    }
}

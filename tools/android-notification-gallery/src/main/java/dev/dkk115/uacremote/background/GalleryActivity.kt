// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.app.Activity
import android.app.Notification
import android.app.PendingIntent
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.TextView
import org.json.JSONObject

/** Isolated CI-only APK. No native owner, Rust/JNA library, network, signing,
 * credential, service, boot receiver or production action handler is linked. */
class GalleryActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
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
        require(selected in setOf("sound", "vibration", "silent", "restore", "withdrawn"))
        val renderer = RequestNotificationRenderer(this)
        renderer.ensureChannels()
        renderer.clearOwned()
        val mode = when (selected) {
            "vibration" -> RequestNotificationMode.VIBRATION_ONLY
            "silent" -> RequestNotificationMode.SILENT
            else -> RequestNotificationMode.SOUND
        }
        if (selected != "withdrawn") {
            val pending = { action: String ->
                PendingIntent.getActivity(this, 0,
                    Intent(this, GalleryActivity::class.java).setAction("gallery.$action")
                        .setData(Uri.parse("gallery://example/$action")),
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            }
            val notification = renderer.build(
                RequestNotificationContent("PowerShell", "C:\\Program Files\\PowerShell\\7\\pwsh.exe"),
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
        }
        filesDir.resolve("gallery-result.json").writeText(JSONObject()
            .put("case", selected).put("nonce", nonce).put("scope", "shared-renderer-only; no production owner/authentication")
            .put("completed", true).toString())
    }
}

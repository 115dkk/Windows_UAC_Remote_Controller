package dev.dkk115.uacremote

import android.os.Bundle
import android.content.Intent
import android.webkit.WebView
import androidx.activity.enableEdgeToEdge
import dev.dkk115.uacremote.background.ControllerForegroundService

class MainActivity : TauriActivity() {
  override fun onWebViewCreate(webView: WebView) {
    super.onWebViewCreate(webView)
    DeviceStatePlugin.actualWebViewCreated(this, webView)
  }

  override fun onDestroy() {
    DeviceStatePlugin.actualActivityDestroyed(this)
    super.onDestroy()
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
    (application as? ControllerApplication)?.receiveRequestIntent(this, intent, savedInstanceState != null)
  }

  override fun onStart() {
    super.onStart()
    // Opening/rotating the Activity must not undo an explicit service stop.
    ControllerForegroundService.startIfEnabled(this)
  }

  override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    (application as? ControllerApplication)?.receiveRequestIntent(this, intent, false)
  }
}

package dev.dkk115.uacremote

import android.os.Bundle
import android.Manifest
import android.content.Intent
import android.content.res.Configuration
import android.webkit.WebView
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import dev.dkk115.uacremote.background.ControllerForegroundService
import dev.dkk115.uacremote.pairing.PairingScannerDialog

class MainActivity : TauriActivity() {
  private var pairingPermissionOwner: PairingScannerDialog? = null
  private val pairingPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
    val original = pairingPermissionOwner
    pairingPermissionOwner = null
    original?.permissionCompleted(granted)
  }
  internal fun pairingPermissionPending(): Boolean = pairingPermissionOwner != null
  internal fun requestPairingCameraPermission(original: PairingScannerDialog): Boolean {
    if (pairingPermissionOwner != null || original.activity !== this || isDestroyed || isFinishing) return false
    pairingPermissionOwner = original
    return try { pairingPermission.launch(Manifest.permission.CAMERA); true }
    catch (_: Exception) { pairingPermissionOwner = null; false }
  }
  override fun onWebViewCreate(webView: WebView) {
    super.onWebViewCreate(webView)
    DeviceStatePlugin.actualWebViewCreated(this, webView)
  }

  override fun onDestroy() {
    (application as? ControllerApplication)?.pairingScannerHostStopped(this)
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

  override fun onStop() {
    (application as? ControllerApplication)?.pairingScannerHostStopped(this)
    super.onStop()
  }

  override fun onConfigurationChanged(newConfig: Configuration) {
    super.onConfigurationChanged(newConfig)
    (application as? ControllerApplication)?.pairingScannerRotationChanged(this)
  }
}

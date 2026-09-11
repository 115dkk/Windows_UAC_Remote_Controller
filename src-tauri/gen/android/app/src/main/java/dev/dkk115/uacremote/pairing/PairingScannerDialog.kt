// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.pairing

import android.util.Log
import android.Manifest
import android.app.Dialog
import android.app.KeyguardManager
import android.content.ComponentName
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.os.UserManager
import android.provider.Settings
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import androidx.camera.view.PreviewView
import androidx.core.view.WindowCompat
import dev.dkk115.uacremote.MainActivity
import dev.dkk115.uacremote.R
import dev.dkk115.uacremote.background.ApplicationPolicyActor

/** One native window/input lifetime, bound to the ORIGINAL Activity and actor. */
internal class PairingScannerDialog(
    val activity: MainActivity,
    private val origin: Any,
    private val actor: ApplicationPolicyActor,
    private val currentHost: () -> Boolean,
    private val finished: (PairingScannerDialog) -> Unit,
) {
    private val main = Handler(Looper.getMainLooper())
    private val started = SystemClock.elapsedRealtime()
    private val ticket = PairingScanTicket()
    private val priorFocus: View? = activity.currentFocus
    private val windowRelease = PairingWindowRelease()
    private var originalDecor: View? = null
    private var showAttempted = false
    private val decorListener = object : View.OnAttachStateChangeListener {
        override fun onViewAttachedToWindow(view: View) = Unit
        override fun onViewDetachedFromWindow(view: View) {
            // Attachment bookkeeping may still be present inside this callback.
            // Observe after it returns, without repeating the dismiss operation.
            if (view === originalDecor) main.post { finishIfReleased() }
        }
    }
    private val dialog = object : Dialog(activity, R.style.Theme_PairingScanner) {
        // Back/cancel and SDK dismiss requests converge on the same one-attempt
        // owner. A callback must never trigger a second underlying dismiss.
        override fun cancel() { this@PairingScannerDialog.close() }
        override fun dismiss() { this@PairingScannerDialog.close() }
        fun dismissOriginalWindow() { super.dismiss() }
    }
    private val content = PairingScannerView(dialog.context, ::close, ::permissionAction)
    private var state = PairingScannerState.PREPARING
    private var closed = false
    private var coreReady = false
    private var actorReleased = true
    private var cameraReleased = true
    private var permissionPending = false
    private var permissionResult: Boolean? = null
    private var camera: PairingCameraSession? = null
    private var completionReported = false
    private val expiry = Runnable { expire() }

    fun belongsTo(host: MainActivity, original: Any): Boolean = activity === host && origin === original
    fun isShowing(): Boolean = !closed && dialog.isShowing

    fun show(): Boolean {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (!live()) { Log.i("UacScan", "stage=show reason=not_live"); return false }
        dialog.setContentView(content)
        dialog.setCanceledOnTouchOutside(false)
        dialog.setOnCancelListener { close() }
        dialog.setOnDismissListener { close() }
        val window = dialog.window ?: return false
        originalDecor = window.decorView
        originalDecor?.addOnAttachStateChangeListener(decorListener)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        val light = activity.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK != Configuration.UI_MODE_NIGHT_YES
        WindowCompat.getInsetsController(window, window.decorView).apply {
            isAppearanceLightStatusBars = light; isAppearanceLightNavigationBars = light
        }
        showAttempted = true // Show may throw after partially attaching its decor.
        dialog.show()
        Log.i("UacScan", "stage=show shown=${dialog.isShowing}")
        window.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
        content.focusHeading()
        if (!live() || !dialog.isShowing) { Log.i("UacScan", "stage=show reason=not_live_after_show"); close(); return false }
        val now = SystemClock.elapsedRealtime()
        if (!PairingScanRules.current(started, now)) { close(); return false }
        val remaining = PairingScanRules.LIFETIME_MILLIS - (now - started)
        if (remaining <= 0 || !main.postDelayed(expiry, remaining)) { close(); return false }
        actorReleased = false
        val owned = actor.beginPairingScan(ticket, { result ->
            if (!live()) { close(); return@beginPairingScan }
            Log.i("UacScan", "stage=begin_scan result=${result.name} cancelled=${ticket.isCancelled()}")
            if (result != PairingScanStart.READY || ticket.isCancelled()) terminal(PairingScannerState.UNAVAILABLE)
            else { coreReady = true; permissionOrCamera() }
        }, { actorReleased = true; finishIfReleased() })
        if (!owned) actorReleased = true
        return true
    }

    private fun live(): Boolean = !closed && PairingScanRules.current(started, SystemClock.elapsedRealtime()) && currentHost() && try {
        activity.getSystemService(UserManager::class.java)?.isUserUnlocked == true &&
            activity.getSystemService(KeyguardManager::class.java)?.isDeviceSecure == true
    } catch (_: Exception) { false }

    private fun render(value: PairingScannerState) {
        if (closed) return
        state = value
        content.render(value, value != PairingScannerState.PERMISSION_SETTINGS || permissionSettingsIntent() != null)
    }

    private fun permissionOrCamera() {
        if (!live() || !coreReady) { close(); return }
        if (activity.checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) startCamera()
        else requestPermission()
    }

    private fun requestPermission() {
        if (!live() || permissionPending || !coreReady) return
        permissionPending = true
        render(PairingScannerState.PERMISSION_PENDING)
        if (!activity.requestPairingCameraPermission(this)) {
            permissionPending = false; terminal(PairingScannerState.UNAVAILABLE)
        }
    }

    /** Invoked only by MainActivity's retained original permission-launch owner. */
    fun permissionCompleted(granted: Boolean) {
        if (closed || !permissionPending) return
        permissionPending = false
        permissionResult = granted
        // Permission UI may temporarily pause this Activity. No camera is opened
        // until the SAME host has actually resumed; no lifetime is renewed.
        if (currentHost()) applyPermissionResult()
    }

    private fun applyPermissionResult() {
        val granted = permissionResult ?: return
        permissionResult = null
        if (!live()) { close(); return }
        if (granted && activity.checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) startCamera()
        else render(if (activity.shouldShowRequestPermissionRationale(Manifest.permission.CAMERA))
            PairingScannerState.PERMISSION_DENIED else PairingScannerState.PERMISSION_SETTINGS)
    }

    fun hostResumed() {
        if (closed) return
        if (!live()) { close(); return }
        applyPermissionResult()
    }

    fun hostPaused() {
        // Only the outstanding original native permission callback may bridge a
        // temporary pause. onStop/destroy always cancels, even during permission.
        if (!permissionPending) close()
    }
    fun rotationChanged() { if (live()) camera?.rotationChanged() else close() }

    private fun startCamera() {
        if (!live() || camera != null || !coreReady || permissionPending) return
        try {
            render(PairingScannerState.PREPARING)
            val preview = PreviewView(dialog.context).apply {
                implementationMode = PreviewView.ImplementationMode.COMPATIBLE
                setBackgroundColor(context.getColor(R.color.pairing_scanner_surface))
                importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            }
            content.attachPreview(preview)
            val session = PairingCameraSession(activity, preview, ::live,
                { if (live()) render(PairingScannerState.SCANNING) else close() },
                ::decoded, { if (!closed) terminal(PairingScannerState.CAMERA_UNAVAILABLE) },
                { cameraReleased = true; content.removePreview(); finishIfReleased() })
            cameraReleased = false
            camera = session
            session.start()
        } catch (_: Exception) {
            terminal(PairingScannerState.CAMERA_UNAVAILABLE)
        }
    }

    private fun decoded(result: OfflineQrResult) {
        if (!live() || state != PairingScannerState.SCANNING) { close(); return }
        camera?.close()
        when (result) {
            OfflineQrResult.Absent -> Unit
            OfflineQrResult.Invalid -> terminal(PairingScannerState.INVALID)
            is OfflineQrResult.Text -> {
                render(PairingScannerState.READING)
                actor.acceptPairingInvitation(ticket, result.value) { value ->
                    if (!live()) { close(); return@acceptPairingInvitation }
                    when (value) {
                        PairingScanRead.READ -> if (!ticket.isCancelled()) render(PairingScannerState.READ) else terminal(PairingScannerState.UNAVAILABLE)
                        PairingScanRead.INVALID -> terminal(PairingScannerState.INVALID)
                        PairingScanRead.UNAVAILABLE -> terminal(PairingScannerState.UNAVAILABLE)
                    }
                }
            }
        }
    }

    private fun terminal(value: PairingScannerState) {
        camera?.close()
        actor.cancelPairingScan(ticket)
        coreReady = false
        render(value)
    }

    private fun expire() {
        if (closed) return
        val now = SystemClock.elapsedRealtime()
        if (currentHost()) terminal(if (PairingScanRules.expired(started, now)) PairingScannerState.EXPIRED else PairingScannerState.UNAVAILABLE)
        else close()
    }

    private fun permissionAction() {
        if (!live()) { close(); return }
        when (state) {
            PairingScannerState.PERMISSION_DENIED -> requestPermission()
            PairingScannerState.PERMISSION_SETTINGS -> {
                val intent = permissionSettingsIntent() ?: return
                close()
                try { activity.startActivity(intent) } catch (_: Exception) { /* no retry or grant */ }
            }
            else -> Unit
        }
    }

    private fun permissionSettingsIntent(): Intent? = try {
        val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", activity.packageName, null))
        val manager = activity.packageManager
        val flags = PackageManager.MATCH_DEFAULT_ONLY or PackageManager.MATCH_SYSTEM_ONLY
        val candidates = if (Build.VERSION.SDK_INT >= 33) manager.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(flags.toLong()))
            else legacyCandidates(manager, intent, flags)
        val info = if (Build.VERSION.SDK_INT >= 33) manager.resolveActivity(intent, PackageManager.ResolveInfoFlags.of(flags.toLong()))?.activityInfo
            else legacyResolve(manager, intent, flags)
        val app = info?.applicationInfo
        val permission = info?.permission
        if (candidates.size > 32 || info == null || candidates.none { it.activityInfo?.let { candidate ->
                candidate.packageName == info.packageName && candidate.name == info.name } == true } ||
            !info.enabled || !info.exported || app == null || !app.enabled ||
            app.flags and ApplicationInfo.FLAG_SYSTEM == 0 ||
            manager.checkSignatures("android", info.packageName) != PackageManager.SIGNATURE_MATCH ||
            (permission != null && activity.checkSelfPermission(permission) != PackageManager.PERMISSION_GRANTED)) null
        else intent.setComponent(ComponentName(info.packageName, info.name))
    } catch (_: Exception) { null }

    @Suppress("DEPRECATION") // API30–32 use the int-flags system resolver.
    private fun legacyResolve(manager: PackageManager, intent: Intent, flags: Int) = manager.resolveActivity(intent, flags)?.activityInfo
    @Suppress("DEPRECATION") // Same fixed system-only query on API30–32.
    private fun legacyCandidates(manager: PackageManager, intent: Intent, flags: Int) = manager.queryIntentActivities(intent, flags)

    fun close() {
        if (closed) { finishIfReleased(); return }
        closed = true; state = PairingScannerState.CLOSED
        main.removeCallbacks(expiry)
        actor.cancelPairingScan(ticket)
        camera?.close()
        if (windowRelease.beginDismiss()) {
            try { dialog.dismissOriginalWindow(); windowRelease.returnedNormally() }
            catch (_: Exception) { windowRelease.failed() }
        }
        finishIfReleased()
    }

    private fun windowReleased(): Boolean = try {
        // Without any show attempt this owner never attached a window. A
        // partially failed show instead requires the exact retained decor.
        val attached = originalDecor?.isAttachedToWindow ?: if (!showAttempted) false else null
        windowRelease.complete(dialog.isShowing, attached)
    } catch (_: Exception) { false }

    private fun finishIfReleased() {
        if (closed && actorReleased && cameraReleased && windowReleased() && !completionReported) {
            completionReported = true
            originalDecor?.removeOnAttachStateChangeListener(decorListener)
            try { if (currentHost() && priorFocus?.isAttachedToWindow == true) priorFocus.requestFocus() }
            catch (_: Exception) { /* Focus delivery is not a window/resource receipt. */ }
            finished(this)
        }
    }
    override fun toString(): String = "PairingScannerDialog([redacted])"
}

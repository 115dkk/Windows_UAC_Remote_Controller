// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote

import android.app.Activity
import android.os.Looper
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity
import app.tauri.annotation.Command
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.lang.ref.WeakReference
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Stable Tauri facade. Native IPC supplies the ORIGINAL physical WebView on
 * Invoke; payload fields, labels and later current-host lookups are not origins.
 * Each entry snapshots one immutable command adapter before any queued work.
 */
@TauriPlugin
class DeviceStatePlugin(activity: Activity) : Plugin(activity) {
    private val application = activity.application as? ControllerApplication
    private var commands: DeviceStateActivityCommands? = null
    private var bound: DeviceStateViewBinding<MainActivity, WebView>? = null

    init {
        if (Looper.myLooper() == Looper.getMainLooper() && activity is MainActivity && application != null) {
            val previous = registered.get()
            if (previous == null || previous === this) {
                registered = WeakReference(this)
                install(bindings.current())
            }
        }
    }

    private fun install(binding: DeviceStateViewBinding<MainActivity, WebView>?) {
        check(Looper.myLooper() == Looper.getMainLooper())
        if (binding === bound) return
        commands?.retire()
        commands = null
        bound = null
        val (activity, webView) = binding?.original() ?: return
        if (activity.application !== application || webView.context !== activity ||
            activity.isDestroyed || activity.isFinishing) return
        val adapter = DeviceStateActivityCommands(activity, webView, binding) {
            try { trigger("request-review", JSObject()) } catch (_: Exception) { }
        }
        bound = binding
        commands = adapter
        adapter.bind()
    }

    override fun load(webView: WebView) {
        val activity = webView.context as? MainActivity ?: return
        actualWebViewCreated(activity, webView)
    }

    override fun onResume() {
        if (Looper.myLooper() == Looper.getMainLooper()) commands?.onResume()
    }

    override fun onDestroy(activity: AppCompatActivity) {
        if (activity is MainActivity) actualActivityDestroyed(activity)
    }

    private fun dispatch(invoke: Invoke, action: (DeviceStateActivityCommands, Invoke) -> Unit) {
        // The SDK origin-bound call carries this object separately from JSON.
        // Snapshot before calling the adapter; no closure reads commands later.
        val origin = invoke.originatingWebView
        val captured = if (Looper.myLooper() == Looper.getMainLooper() && origin != null) {
            commands?.takeIf { it.matches(origin) }
        } else null
        if (captured == null) {
            // Fixed-token CI diagnostic: which command was refused and why (thread or origin), never payloads.
            android.util.Log.i("UacScan", "stage=dispatch rejected command=${invoke.command} main=${Looper.myLooper() == Looper.getMainLooper()} origin=${origin != null} bound=${commands != null}")
            try { invoke.reject("휴대폰 상태를 확인하지 못했어요.", "mobile_state_unavailable") } catch (_: Exception) { }
            return
        }
        action(captured, invoke)
    }

    @Command fun controllerRequests(invoke: Invoke) = dispatch(invoke, DeviceStateActivityCommands::controllerRequests)
    @Command fun controllerRequestDetails(invoke: Invoke) = dispatch(invoke, DeviceStateActivityCommands::controllerRequestDetails)
    @Command fun controllerRequestReview(invoke: Invoke) = dispatch(invoke, DeviceStateActivityCommands::controllerRequestReview)
    @Command fun controllerRequestAction(invoke: Invoke) = dispatch(invoke, DeviceStateActivityCommands::controllerRequestAction)
    @Command fun controllerService(invoke: Invoke) = dispatch(invoke, DeviceStateActivityCommands::controllerService)
    @Command fun startControllerService(invoke: Invoke) = dispatch(invoke, DeviceStateActivityCommands::startControllerService)
    @Command fun stopControllerService(invoke: Invoke) = dispatch(invoke, DeviceStateActivityCommands::stopControllerService)
    @Command fun controllerPolicy(invoke: Invoke) = dispatch(invoke, DeviceStateActivityCommands::controllerPolicy)
    @Command fun controllerHistory(invoke: Invoke) = dispatch(invoke, DeviceStateActivityCommands::controllerHistory)
    @Command fun clearControllerHistory(invoke: Invoke) = dispatch(invoke, DeviceStateActivityCommands::clearControllerHistory)
    @Command fun saveControllerPolicy(invoke: Invoke) = dispatch(invoke, DeviceStateActivityCommands::saveControllerPolicy)
    @Command fun readiness(invoke: Invoke) = dispatch(invoke, DeviceStateActivityCommands::readiness)
    @Command fun openPairingScanner(invoke: Invoke) = dispatch(invoke, DeviceStateActivityCommands::openPairingScanner)
    @Command fun openLockSettings(invoke: Invoke) = dispatch(invoke, DeviceStateActivityCommands::openLockSettings)
    @Command fun openNotificationSettings(invoke: Invoke) = dispatch(invoke, DeviceStateActivityCommands::openNotificationSettings)

    companion object {
        private val bindings = DeviceStateBindingSlot<MainActivity, WebView>()
        private var registered = WeakReference<DeviceStatePlugin>(null)

        /** Only the actual MainActivity.onWebViewCreate / SDK load callback calls
         * this. Remembering a weak pending binding closes either construction order. */
        internal fun actualWebViewCreated(activity: MainActivity, webView: WebView) {
            if (Looper.myLooper() != Looper.getMainLooper() || webView.context !== activity ||
                activity.application !is ControllerApplication || activity.isDestroyed || activity.isFinishing) return
            val facade = registered.get()
            if (facade != null && facade.application !== activity.application) return
            val binding = bindings.created(activity, webView)
            facade?.install(binding)
        }

        internal fun actualActivityDestroyed(activity: MainActivity) {
            if (Looper.myLooper() != Looper.getMainLooper()) return
            if (bindings.destroyed(activity)) registered.get()?.install(null)
        }
    }
}

/** Bounded identity bookkeeping; callers supply real objects, never numeric IDs.
 * No Activity/Invoke mutation occurs in these pure state helpers. */
internal class DeviceStateViewBinding<H : Any, V : Any>(host: H, view: V) {
    private val host = WeakReference(host)
    private val view = WeakReference(view)
    private val live = AtomicBoolean(true)
    fun matches(host: H, view: V): Boolean = live.get() && this.host.get() === host && this.view.get() === view
    fun owns(host: H): Boolean = this.host.get() === host
    fun original(): Pair<H, V>? {
        if (!live.get()) return null
        val host = host.get() ?: return null
        val view = view.get() ?: return null
        return if (live.get()) host to view else null
    }
    fun retire() { live.set(false) }
}

internal class DeviceStateBindingSlot<H : Any, V : Any> {
    private var binding: DeviceStateViewBinding<H, V>? = null
    fun current(): DeviceStateViewBinding<H, V>? = binding?.takeIf { it.original() != null }
    fun created(host: H, view: V): DeviceStateViewBinding<H, V> {
        binding?.takeIf { it.matches(host, view) }?.let { return it }
        binding?.retire()
        return DeviceStateViewBinding(host, view).also { binding = it }
    }
    fun destroyed(host: H): Boolean {
        val held = binding ?: return false
        if (!held.owns(host)) return false
        held.retire()
        binding = null
        return true
    }
}

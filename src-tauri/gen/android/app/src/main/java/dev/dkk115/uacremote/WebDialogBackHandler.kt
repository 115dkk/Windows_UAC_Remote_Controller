// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote

import android.os.Handler
import android.os.Looper
import android.webkit.WebView
import androidx.activity.OnBackPressedCallback

/** Presentation-only Back routing for the original Activity's physical WebView.
 * No web/native command endpoint is added. Native windows retain their own Back
 * dispatch; this fixed script can only request cancellation of a web dialog.
 */
internal class WebDialogBackHandler(
    private val activity: MainActivity,
    private val webView: WebView,
) {
    private val main = Handler(Looper.getMainLooper())
    private var pending: Any? = null
    private var retired = false
    private var timeout: Runnable? = null
    private val callback = object : OnBackPressedCallback(true) {
        override fun handleOnBackPressed() {
            if (pending != null || !current()) return
            val attempt = Any()
            pending = attempt
            // A lost/late JS reply consumes this press, never exits later or
            // replays cancellation against a replacement Activity/WebView.
            val expiry = Runnable { if (pending === attempt) invalidate() }
            timeout = expiry
            main.postDelayed(expiry, 2_000L)
            try {
                webView.evaluateJavascript(CANCEL_DIALOG) { result ->
                    if (pending !== attempt) return@evaluateJavascript
                    invalidate()
                    if (result == "false" && current()) {
                        isEnabled = false
                        try { activity.onBackPressedDispatcher.onBackPressed() }
                        finally { if (!retired) isEnabled = true }
                    }
                }
            } catch (_: Exception) { invalidate() }
        }
    }

    init { activity.onBackPressedDispatcher.addCallback(activity, callback) }

    private fun current(): Boolean = !retired && !activity.isDestroyed && !activity.isFinishing &&
        webView.context === activity && webView.isAttachedToWindow &&
        webView.rootView === activity.window.decorView && activity.hasWindowFocus() &&
        (activity.application as? ControllerApplication)?.isCurrentForegroundControllerHost(activity) == true

    fun invalidate() {
        pending = null
        timeout?.let(main::removeCallbacks)
        timeout = null
    }

    fun retire() { retired = true; invalidate(); callback.remove() }

    companion object {
        // Match only the owned React dialog family. Dispatch the same cancel
        // event as Escape: LanguageSettings discards its draft, while a save in
        // progress prevents cancellation and still consumes Back. Never click
        // a confirmation/apply button or infer native authorization from DOM.
        private val CANCEL_DIALOG = """
            (() => {
              const dialogs = document.querySelectorAll('dialog.confirm-dialog[open]');
              const dialog = dialogs[dialogs.length - 1];
              if (!dialog) return false;
              dialog.dispatchEvent(new Event('cancel', { cancelable: true }));
              return true;
            })()
        """.trimIndent()
    }
}

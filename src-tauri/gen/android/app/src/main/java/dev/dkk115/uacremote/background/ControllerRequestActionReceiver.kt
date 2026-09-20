// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.Looper
import dev.dkk115.uacremote.ControllerApplication
import java.util.concurrent.atomic.AtomicBoolean

/** Nonexported fixed denial route. Extras are never authority; no Activity,
 * owner creation, permission prompt, authentication or service restart here. */
class ControllerRequestActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val route = try { NativeRequestRules.route(intent) } catch (_: Exception) { null } ?: return
        if (route.action != NativeRequestAction.DENY) return
        val app = context.applicationContext as? ControllerApplication ?: return
        val pending = goAsync()
        val main = Handler(Looper.getMainLooper())
        val finished = AtomicBoolean(false)
        val timeout = Runnable { if (finished.compareAndSet(false, true)) pending.finish() }
        if (!main.postDelayed(timeout, 8_000L)) { pending.finish(); return }
        try {
            app.denyNotificationRequest(route) {
                if (finished.compareAndSet(false, true)) { main.removeCallbacks(timeout); pending.finish() }
            }
        } catch (_: Exception) {
            if (finished.compareAndSet(false, true)) { main.removeCallbacks(timeout); pending.finish() }
        }
        // Receiver completion is not decision delivery. The retained actor job
        // owns any already accepted denial beyond this bounded broadcast lease.
    }
}

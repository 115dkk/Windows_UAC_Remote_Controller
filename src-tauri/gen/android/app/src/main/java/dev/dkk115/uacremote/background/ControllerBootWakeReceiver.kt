// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Stable manifest-enabled wake path, NEVER toggled by product code. Actual
 * DE choice gates FGS; this receiver never opens CE, creates keys or launches UI. */
class ControllerBootWakeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (!BootServicePolicy.acceptsBootAction(intent.action)) return
        val category = BootDiagnostics.bootAction(intent.action)
        BootDiagnostics.record(BootDiagnosticRecord(BootDiagnosticStage.RECEIVER_ACCEPTED,
            action = category, component = ControllerForegroundService.componentState(context),
            unlock = ControllerForegroundService.observeUnlock(context)))
        val pending = goAsync()
        try {
            ControllerForegroundService.startIfEnabled(context.applicationContext) { result ->
                try { BootDiagnostics.record(BootDiagnosticRecord(BootDiagnosticStage.RECEIVER_RESULT, action = category, result = result)) }
                finally { pending.finish() }
            }
        } catch (_: Exception) { pending.finish() }
    }
}

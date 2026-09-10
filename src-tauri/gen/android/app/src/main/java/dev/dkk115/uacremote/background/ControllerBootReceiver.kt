// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** System boot/update trigger only. No files, Rust owner, keys, UI or retry loop. */
class ControllerBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action
        if (!BootServicePolicy.acceptsBootAction(action)) return
        val category = BootDiagnostics.bootAction(action)
        // These are diagnostic observations, not cached inputs to admission.
        BootDiagnostics.record(BootDiagnosticRecord(BootDiagnosticStage.RECEIVER_ACCEPTED,
            action = category, component = ControllerForegroundService.componentState(context),
            unlock = ControllerForegroundService.observeUnlock(context)))
        val result = ControllerForegroundService.startIfEnabled(context)
        BootDiagnostics.record(BootDiagnosticRecord(BootDiagnosticStage.RECEIVER_RESULT,
            action = category, result = result))
    }
}

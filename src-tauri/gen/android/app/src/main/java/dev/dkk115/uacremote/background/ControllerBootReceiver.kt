// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** System boot/update trigger only. No files, Rust owner, keys, UI or retry loop. */
class ControllerBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (!BootServicePolicy.acceptsBootAction(intent.action)) return
        ControllerForegroundService.startIfEnabled(context)
    }
}

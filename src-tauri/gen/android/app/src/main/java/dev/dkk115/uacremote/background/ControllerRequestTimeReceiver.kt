// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import dev.dkk115.uacremote.ControllerApplication

/** Fixed OS time/zone wake only. No clock data is trusted from Intent extras. */
class ControllerRequestTimeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_TIME_CHANGED && intent.action != Intent.ACTION_TIMEZONE_CHANGED && intent.action != Intent.ACTION_DATE_CHANGED) return
        (context.applicationContext as? ControllerApplication)?.requestTimeChanged()
    }
}

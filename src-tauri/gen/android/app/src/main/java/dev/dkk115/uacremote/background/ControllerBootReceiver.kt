// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Filterless legacy component. Its OS enabled state is read only by migration;
 * it never starts work, even if an old queued broadcast reaches this version. */
class ControllerBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) = Unit
}

// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import java.util.concurrent.atomic.AtomicBoolean

/** Stateless policy over the EXISTING callback gate and exact-close cursor.
 * No new registry, key owner, automatic retry, alias deletion or authority. */
internal object CreationArgumentCleanupPolicy {
    fun ready(active: AtomicBoolean, arguments: DenialCloseCursor): Boolean =
        !active.get() && arguments.complete()

    /** Only the Application explicit shutdown branch may grant this one retry. */
    fun retryExplicitly(active: AtomicBoolean, arguments: DenialCloseCursor): Boolean {
        if (!active.compareAndSet(false, true)) return false
        return try { arguments.retryOnce() }
        finally { active.set(false) }
    }
}

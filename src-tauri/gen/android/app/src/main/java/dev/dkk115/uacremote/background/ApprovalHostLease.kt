// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

/**
 * Identity/lifecycle only, never authentication evidence. A new Activity or a
 * new explicit request gets a new lease. Covering the Activity with Android's
 * credential UI suspends completion without canceling that credential prompt.
 */
internal class ApprovalHostLease(private val host: Any) {
    private var active = true
    private var resumed = true

    @Synchronized fun isCurrent(candidate: Any): Boolean = active && candidate === host
    @Synchronized fun mayComplete(candidate: Any): Boolean = active && resumed && candidate === host
    @Synchronized fun resumed(candidate: Any): Boolean {
        if (!active || candidate !== host) return false
        resumed = true
        return true
    }
    @Synchronized fun paused(candidate: Any) {
        if (candidate === host) resumed = false
    }
    @Synchronized fun invalidate() { active = false; resumed = false }
    override fun toString(): String = "ApprovalHostLease([redacted], lifecycle_only)"
}

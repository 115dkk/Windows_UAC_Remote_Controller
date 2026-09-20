// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

/** Timing for cleanup admission only, never authentication or quiescence proof.
 * Busy before retireApproval admission has performed no retirement. It must not
 * spend the budget for failed cleanup operations or spin on worker finally. */
internal class ApprovalCleanupAdmission {
    private var nextMillis = FIRST_MILLIS
    private var waits = 0

    @Synchronized fun defer(): Long {
        val delay = nextMillis
        nextMillis = (nextMillis * 2).coerceAtMost(MAX_MILLIS)
        if (waits < Int.MAX_VALUE) waits++
        return delay
    }

    @Synchronized fun waits(): Int = waits

    companion object {
        const val FIRST_MILLIS = 50L
        const val MAX_MILLIS = 1_000L
    }
}

// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

/**
 * Timing for one approval session's jobs when the native owner answers Busy.
 *
 * Busy from beginApproval, claimApproval or finishApproval is the owner's
 * admission: another thread held it, the call did not start, and the plan, the
 * claim and the signature the job was holding are exactly as they were. The
 * job used to cancel the session on that answer, so a person who had already
 * passed the identity check lost the signature it produced and was shown the
 * request again as if nothing had been pressed.
 *
 * The same job runs again instead. This is neither an authentication retry nor
 * a signing retry: the prompt is not shown again and nothing is signed twice.
 * A Busy that did reach the owner leaves a cancelled plan behind, and the
 * repeated call is then refused by the owner itself. The session's own
 * deadline still ends it, and so does this budget.
 */
internal class ApprovalBusyRetry {
    private var waits = 0

    /** Delay before the same job runs again, or null once the budget is spent. */
    @Synchronized fun next(): Long? {
        if (waits >= DELAYS_MILLIS.size) return null
        return DELAYS_MILLIS[waits].also { waits += 1 }
    }

    @Synchronized fun waits(): Int = waits

    companion object {
        /** Short first, because the owner is normally held for one message. */
        val DELAYS_MILLIS = longArrayOf(25L, 50L, 100L, 200L, 400L, 400L)
    }
}

// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import dev.dkk115.uacremote.nativecore.BridgeException

/** Request rejection is not owner loss. This deliberately does NOT adopt the
 * intake's broader survivable-error set: action/storage/native ambiguity still
 * requires its existing fail-closed owner path. No retry/signing permit. */
internal object RequestActionFailurePolicy {
    fun requestLocal(failure: Throwable): Boolean = when (failure) {
        is BridgeException.Busy,
        is BridgeException.ApprovalRejected,
        is BridgeException.DenialRejected,
        is BridgeException.RequestUnavailable,
        is BridgeException.PresentationRefreshRequired,
        is BridgeException.InvalidPolicy,
        is BridgeException.HistoryTimeUnavailable -> true
        else -> false
    }

    fun approvalRetiresOwner(failure: Throwable): Boolean =
        failure is BridgeException && !requestLocal(failure)

    /** Cleanup is not a request operation. A local-looking failure while closing
     * an exact wrapper must retain the original stricter uncertainty behavior. */
    fun approvalCleanupRetiresOwner(failure: Throwable): Boolean = failure is BridgeException &&
        failure !is BridgeException.ApprovalRejected && failure !is BridgeException.Busy &&
        failure !is BridgeException.InvalidPolicy && failure !is BridgeException.HistoryTimeUnavailable
}

internal enum class DenialRejectionCleanup { RELEASE_EMPTY, SETTLE_ORIGINAL, RETAIN_FAILED }

/** Selection from actual owned fields AFTER cancellation/input cleanup. Only
 * typed request-local reserve rejection proves no Rust scope was inserted. */
internal object DenialRejectionPolicy {
    fun cleanup(reserving: Boolean, hasScope: Boolean, scopeClosed: Boolean,
                hasNativeInputs: Boolean, cleanupCertain: Boolean): DenialRejectionCleanup = when {
        !cleanupCertain || scopeClosed -> DenialRejectionCleanup.RETAIN_FAILED
        hasScope -> DenialRejectionCleanup.SETTLE_ORIGINAL
        reserving && !hasNativeInputs -> DenialRejectionCleanup.RELEASE_EMPTY
        else -> DenialRejectionCleanup.RETAIN_FAILED
    }
}

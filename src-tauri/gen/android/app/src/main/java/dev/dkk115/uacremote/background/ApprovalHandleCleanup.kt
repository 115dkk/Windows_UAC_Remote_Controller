// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

internal enum class ApprovalHandleCleanupAction { RETIRE, CLOSE_ATTEMPT, CLOSE_PLAN, COMPLETE }

/**
 * Pure cleanup progress, not a native handle owner or authentication assertion.
 * The coordinator holds its session.handleLock while reading/advancing this
 * state and calls completed ONLY after the selected native operation returns
 * successfully. An exception leaves that action (and later actions) pending.
 * Keep the coordinator slot occupied until COMPLETE; never reset this object.
 */
internal class ApprovalHandleCleanup {
    private var pending = ApprovalHandleCleanupAction.RETIRE

    fun next(): ApprovalHandleCleanupAction = pending

    fun completed(action: ApprovalHandleCleanupAction) {
        require(action == pending) { "Invalid approval handle cleanup order" }
        pending = when (action) {
            ApprovalHandleCleanupAction.RETIRE -> ApprovalHandleCleanupAction.CLOSE_ATTEMPT
            ApprovalHandleCleanupAction.CLOSE_ATTEMPT -> ApprovalHandleCleanupAction.CLOSE_PLAN
            ApprovalHandleCleanupAction.CLOSE_PLAN -> ApprovalHandleCleanupAction.COMPLETE
            ApprovalHandleCleanupAction.COMPLETE -> ApprovalHandleCleanupAction.COMPLETE
        }
    }

    fun planClosed(): Boolean = pending == ApprovalHandleCleanupAction.COMPLETE

    override fun toString(): String = "ApprovalHandleCleanup(cleanup_progress_only)"
}

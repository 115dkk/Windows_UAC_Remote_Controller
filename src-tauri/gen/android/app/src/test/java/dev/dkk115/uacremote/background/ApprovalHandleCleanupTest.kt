// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure synthetic step outcomes; no Android, generated handles or native calls. */
class ApprovalHandleCleanupTest {
    @Test fun initialOrderRetiresThenClosesAttemptThenPlan() {
        val cleanup = ApprovalHandleCleanup()
        for (action in listOf(ApprovalHandleCleanupAction.RETIRE,
            ApprovalHandleCleanupAction.CLOSE_ATTEMPT, ApprovalHandleCleanupAction.CLOSE_PLAN)) {
            assertEquals(action, cleanup.next())
            cleanup.completed(action)
        }
        assertEquals(ApprovalHandleCleanupAction.COMPLETE, cleanup.next())
    }

    @Test fun uncompletedFailedStepRemainsTheExactRetryTarget() {
        val cleanup = ApprovalHandleCleanup()
        for (action in listOf(ApprovalHandleCleanupAction.RETIRE,
            ApprovalHandleCleanupAction.CLOSE_ATTEMPT, ApprovalHandleCleanupAction.CLOSE_PLAN)) {
            // A simulated external throw performs no completed() call. Earlier
            // successes stay recorded; no later action is exposed prematurely.
            repeat(3) { assertEquals(action, cleanup.next()) }
            cleanup.completed(action)
        }
        assertEquals(ApprovalHandleCleanupAction.COMPLETE, cleanup.next())
    }

    @Test fun successfulStepsAreNeverRepeatedOnLaterCleanupAttempts() {
        val cleanup = ApprovalHandleCleanup()
        cleanup.completed(ApprovalHandleCleanupAction.RETIRE)
        reject(cleanup, ApprovalHandleCleanupAction.RETIRE)
        assertEquals(ApprovalHandleCleanupAction.CLOSE_ATTEMPT, cleanup.next())
        cleanup.completed(ApprovalHandleCleanupAction.CLOSE_ATTEMPT)
        reject(cleanup, ApprovalHandleCleanupAction.CLOSE_ATTEMPT)
        assertEquals(ApprovalHandleCleanupAction.CLOSE_PLAN, cleanup.next())
        cleanup.completed(ApprovalHandleCleanupAction.CLOSE_PLAN)
        reject(cleanup, ApprovalHandleCleanupAction.CLOSE_PLAN)
        assertEquals(ApprovalHandleCleanupAction.COMPLETE, cleanup.next())
    }

    @Test fun outOfOrderCompletionRejectsWithoutAdvancing() {
        val cleanup = ApprovalHandleCleanup()
        for (action in listOf(ApprovalHandleCleanupAction.CLOSE_ATTEMPT,
            ApprovalHandleCleanupAction.CLOSE_PLAN, ApprovalHandleCleanupAction.COMPLETE)) {
            reject(cleanup, action)
            assertEquals(ApprovalHandleCleanupAction.RETIRE, cleanup.next())
        }
        cleanup.completed(ApprovalHandleCleanupAction.RETIRE)
        reject(cleanup, ApprovalHandleCleanupAction.CLOSE_PLAN)
        reject(cleanup, ApprovalHandleCleanupAction.COMPLETE)
        assertEquals(ApprovalHandleCleanupAction.CLOSE_ATTEMPT, cleanup.next())
    }

    @Test fun planClosedOnlyAfterSuccessfulPlanClose() {
        val cleanup = ApprovalHandleCleanup()
        assertFalse(cleanup.planClosed())
        cleanup.completed(ApprovalHandleCleanupAction.RETIRE)
        assertFalse(cleanup.planClosed())
        cleanup.completed(ApprovalHandleCleanupAction.CLOSE_ATTEMPT)
        assertFalse(cleanup.planClosed())
        // A failed/unperformed close cannot publish slot-free or plan-closed.
        assertEquals(ApprovalHandleCleanupAction.CLOSE_PLAN, cleanup.next())
        assertFalse(cleanup.planClosed())
        cleanup.completed(ApprovalHandleCleanupAction.CLOSE_PLAN)
        assertTrue(cleanup.planClosed())
    }

    @Test fun completeIsIdempotentOnlyWhenItIsTheSelectedAction() {
        val cleanup = ApprovalHandleCleanup()
        reject(cleanup, ApprovalHandleCleanupAction.COMPLETE)
        cleanup.completed(ApprovalHandleCleanupAction.RETIRE)
        cleanup.completed(ApprovalHandleCleanupAction.CLOSE_ATTEMPT)
        cleanup.completed(ApprovalHandleCleanupAction.CLOSE_PLAN)
        repeat(3) {
            cleanup.completed(ApprovalHandleCleanupAction.COMPLETE)
            assertEquals(ApprovalHandleCleanupAction.COMPLETE, cleanup.next())
            assertTrue(cleanup.planClosed())
        }
    }

    private fun reject(cleanup: ApprovalHandleCleanup, action: ApprovalHandleCleanupAction) {
        val before = cleanup.next()
        var rejected = false
        try { cleanup.completed(action) }
        catch (_: IllegalArgumentException) { rejected = true }
        assertTrue(rejected)
        assertEquals(before, cleanup.next())
    }
}

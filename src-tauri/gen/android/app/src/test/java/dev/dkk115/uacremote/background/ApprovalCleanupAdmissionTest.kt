// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ApprovalCleanupAdmissionTest {
    @Test fun contentionBeyondTheOldFailureBudgetRetainsExactlyTheRetirementStep() {
        val admission = ApprovalCleanupAdmission()
        val cleanup = ApprovalHandleCleanup()
        val delays = mutableListOf<Long>()
        repeat(12) {
            // No native call was admitted. No completed() and no wrapper close.
            delays.add(admission.defer())
            assertEquals(ApprovalHandleCleanupAction.RETIRE, cleanup.next())
            assertFalse(cleanup.planClosed())
        }
        assertEquals(listOf(50L, 100L, 200L, 400L, 800L, 1000L), delays.take(6))
        assertTrue(delays.all { it in 50L..1000L })
        assertEquals(12, admission.waits())
        val executed = mutableListOf<ApprovalHandleCleanupAction>()
        while (cleanup.next() != ApprovalHandleCleanupAction.COMPLETE) {
            val step = cleanup.next()
            executed.add(step)
            cleanup.completed(step)
        }
        assertEquals(listOf(ApprovalHandleCleanupAction.RETIRE, ApprovalHandleCleanupAction.CLOSE_ATTEMPT,
            ApprovalHandleCleanupAction.CLOSE_PLAN), executed)
        assertTrue(cleanup.planClosed())
    }

    @Test fun realCloseFailureRemainsPendingEvenAfterAdmissionSucceeds() {
        val cleanup = ApprovalHandleCleanup()
        cleanup.completed(ApprovalHandleCleanupAction.RETIRE)
        repeat(10) { assertEquals(ApprovalHandleCleanupAction.CLOSE_ATTEMPT, cleanup.next()) }
        assertFalse(cleanup.planClosed())
    }
}

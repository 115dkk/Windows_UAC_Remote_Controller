// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import java.util.ArrayDeque
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ApprovalCleanupOwnerTest {
    @Test fun cleanupStartsOnlyWhenItsOwnedConditionsPermitItsOwnedResources() {
        val fixture = Fixture()
        fixture.operation.quiescent = false

        fixture.owner.requestCleanup()
        fixture.owner.terminal()
        fixture.owner.jobStarted()
        fixture.owner.requestCleanup()
        fixture.owner.jobFinished()
        fixture.owner.requestCleanup()

        assertTrue(fixture.workers.isEmpty())
        assertEquals(
            listOf(
                ApprovalCleanupRefusal.NOT_TERMINAL,
                ApprovalCleanupRefusal.JOBS_OUTSTANDING,
                ApprovalCleanupRefusal.OPERATION_BUSY,
            ),
            fixture.refusals,
        )

        fixture.operation.quiescent = true
        fixture.owner.requestCleanup()
        fixture.runWorker()

        assertEquals(
            listOf(
                ApprovalCleanupAction.CLOSE_SUBMISSION,
                ApprovalCleanupAction.RETIRE,
                ApprovalCleanupAction.CLOSE_ATTEMPT,
                ApprovalCleanupAction.CLOSE_PLAN,
            ),
            fixture.platform.calls,
        )
        assertEquals(1, fixture.completions)
        assertTrue(fixture.owner.complete())
    }

    @Test fun retirementBusyKeepsTheSlotAndDoesNotRepeatSuccessfulCleanup() {
        val fixture = Fixture()
        fixture.platform.failOnce(ApprovalCleanupAction.RETIRE, OwnerBusy())
        fixture.owner.terminal()
        fixture.owner.requestCleanup()
        fixture.runWorker()

        assertFalse(fixture.owner.failed())
        assertFalse(fixture.owner.complete())
        assertEquals(1, fixture.delayed.size)
        assertEquals(
            listOf(ApprovalCleanupAction.CLOSE_SUBMISSION, ApprovalCleanupAction.RETIRE),
            fixture.platform.calls,
        )

        fixture.runDelayed()
        fixture.runWorker()

        assertEquals(1, fixture.platform.calls.count { it == ApprovalCleanupAction.CLOSE_SUBMISSION })
        assertEquals(2, fixture.platform.calls.count { it == ApprovalCleanupAction.RETIRE })
        assertEquals(1, fixture.platform.calls.count { it == ApprovalCleanupAction.CLOSE_ATTEMPT })
        assertEquals(1, fixture.platform.calls.count { it == ApprovalCleanupAction.CLOSE_PLAN })
        assertEquals(1, fixture.completions)
        assertEquals(1, fixture.completedAdmissionWaits)
    }

    @Test fun aFailedCloseResumesAtThatExactResource() {
        val fixture = Fixture()
        fixture.platform.failOnce(ApprovalCleanupAction.CLOSE_ATTEMPT, CloseFailure())
        fixture.owner.terminal()
        fixture.owner.requestCleanup()
        fixture.runWorker()

        assertTrue(fixture.owner.failed())
        assertEquals(0, fixture.completions)
        assertTrue(fixture.owner.retryFailed(3))
        fixture.owner.requestCleanup()
        fixture.runWorker()

        assertEquals(1, fixture.platform.calls.count { it == ApprovalCleanupAction.CLOSE_SUBMISSION })
        assertEquals(1, fixture.platform.calls.count { it == ApprovalCleanupAction.RETIRE })
        assertEquals(2, fixture.platform.calls.count { it == ApprovalCleanupAction.CLOSE_ATTEMPT })
        assertEquals(1, fixture.platform.calls.count { it == ApprovalCleanupAction.CLOSE_PLAN })
        assertEquals(1, fixture.completions)
    }

    private class Fixture {
        val workers = ArrayDeque<() -> Unit>()
        val delayed = ArrayDeque<() -> Unit>()
        val platform = FakePlatform()
        val operation = Operation()
        val refusals = mutableListOf<ApprovalCleanupRefusal>()
        var completions = 0
        var completedAdmissionWaits = -1
        val owner = ApprovalCleanupOwner(
            platform = platform,
            enqueue = { workers.addLast(it); true },
            defer = { _, work -> delayed.addLast(work); true },
            onComplete = { waits -> completions++; completedAdmissionWaits = waits },
            onRefused = { refusals += it },
        ).apply {
            bindPlan(Plan())
            bindAttempt(Attempt())
            bindOperation(operation)
            holdSubmission(Submission())
        }

        fun runWorker() = workers.removeFirst().invoke()
        fun runDelayed() = delayed.removeFirst().invoke()
    }

    private class FakePlatform : ApprovalCleanupPlatform<Plan, Attempt, Submission, Operation> {
        val calls = mutableListOf<ApprovalCleanupAction>()
        private val failures = mutableMapOf<ApprovalCleanupAction, Throwable>()

        fun failOnce(action: ApprovalCleanupAction, failure: Throwable) { failures[action] = failure }
        private fun step(action: ApprovalCleanupAction) {
            calls += action
            failures.remove(action)?.let { throw it }
        }

        override fun closeSubmission(submission: Submission) = step(ApprovalCleanupAction.CLOSE_SUBMISSION)
        override fun retire(plan: Plan) = step(ApprovalCleanupAction.RETIRE)
        override fun closeAttempt(attempt: Attempt) = step(ApprovalCleanupAction.CLOSE_ATTEMPT)
        override fun closePlan(plan: Plan) = step(ApprovalCleanupAction.CLOSE_PLAN)
        override fun operationQuiescent(operation: Operation): Boolean = operation.quiescent
        override fun cancelPlan(plan: Plan) = Unit
        override fun planCancelled(plan: Plan): Boolean = false
        override fun retirementBusy(failure: Throwable): Boolean = failure is OwnerBusy
    }

    private class Plan
    private class Attempt
    private class Submission
    private class Operation(var quiescent: Boolean = true)
    private class OwnerBusy : RuntimeException()
    private class CloseFailure : RuntimeException()
}

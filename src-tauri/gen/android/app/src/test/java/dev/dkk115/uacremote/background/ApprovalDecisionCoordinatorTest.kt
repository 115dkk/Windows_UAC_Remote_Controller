// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import java.util.ArrayDeque
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ApprovalDecisionCoordinatorTest {
    @Test fun nativeFailureAfterAcceptedDecisionReleasesTheSlot() {
        val fixture = Fixture()
        fixture.finish += { throw NativeFailure() }

        assertTrue(fixture.coordinator.accept(fixture.decision))
        assertTrue(fixture.coordinator.start())
        fixture.runWorker()

        assertEquals(1, fixture.failures)
        assertEquals(1, fixture.cleanups)
        assertFalse(fixture.coordinator.hasPendingDecision())
        assertTrue(fixture.decision.all { it == 0.toByte() })
    }

    @Test fun aBusyOwnerRetriesTheSameDecisionWithoutAcceptingAnotherDecision() {
        val fixture = Fixture()
        fixture.finish += { throw OwnerBusy() }
        fixture.finish += { Submission() }

        assertTrue(fixture.coordinator.accept(fixture.decision))
        assertFalse(fixture.coordinator.accept(byteArrayOf(9, 9, 9)))
        assertTrue(fixture.coordinator.start())
        fixture.runWorker()
        assertEquals(1, fixture.delayed.size)
        fixture.runDelayed()
        fixture.runWorker()

        assertEquals(listOf(listOf<Byte>(1, 2, 3), listOf<Byte>(1, 2, 3)), fixture.finishInputs)
        assertEquals(1, fixture.prepared)
        assertEquals(0, fixture.failures)
        assertEquals(0, fixture.cleanups)
        assertFalse(fixture.coordinator.hasPendingDecision())
    }

    @Test fun cancellationMidFlightCleansUpOnceAndReleasesTheSlot() {
        val fixture = Fixture()
        val late = Submission()
        fixture.finish += {
            assertTrue(fixture.coordinator.cancel())
            late
        }

        assertTrue(fixture.coordinator.accept(fixture.decision))
        assertTrue(fixture.coordinator.start())
        fixture.runWorker()

        assertEquals(1, late.closes)
        assertEquals(1, fixture.cleanups)
        assertFalse(fixture.coordinator.hasPendingDecision())
        assertFalse(fixture.coordinator.cancel())
        assertEquals(1, fixture.cleanups)
    }

    @Test fun aLateBusyRetryAfterCleanupIsIgnored() {
        val fixture = Fixture()
        fixture.finish += { throw OwnerBusy() }

        assertTrue(fixture.coordinator.accept(fixture.decision))
        assertTrue(fixture.coordinator.start())
        fixture.runWorker()
        assertEquals(1, fixture.delayed.size)

        assertTrue(fixture.coordinator.cancel())
        assertEquals(1, fixture.cleanups)
        fixture.runDelayed()

        assertTrue(fixture.workers.isEmpty())
        assertEquals(1, fixture.finishInputs.size)
        assertEquals(1, fixture.cleanups)
        assertFalse(fixture.coordinator.hasPendingDecision())
    }

    @Test fun cancellationInsideFinishKeepsRealCleanupResourcesUntilTheDecisionJobFinishes() {
        val cleanup = CleanupHarness()
        val workers = ArrayDeque<() -> Unit>()
        val returned = Submission()
        var cancellationAccepted = false
        var jobsInsideFinish = -1
        lateinit var coordinator: ApprovalDecisionCoordinator<Submission>
        coordinator = ApprovalDecisionCoordinator(
            platform = object : ApprovalDecisionPlatform<Submission> {
                override fun finish(signedDecision: ByteArray): Submission {
                    jobsInsideFinish = cleanup.owner.jobs()
                    cleanup.owner.terminal()
                    cancellationAccepted = coordinator.cancel()
                    return returned
                }
                override fun close(submission: Submission) { submission.closes++ }
                override fun busy(failure: Throwable): Boolean = false
            },
            enqueue = { workers.addLast(it); true },
            defer = { _, _ -> false },
            onPrepared = { false },
            onFailure = {},
            cleanup = cleanup.owner::requestCleanup,
            onJobStarted = cleanup.owner::jobStarted,
            onJobFinished = {
                cleanup.owner.jobFinished()
                cleanup.decisionJobActive = false
            },
        )

        assertTrue(coordinator.accept(byteArrayOf(1, 2, 3)))
        assertTrue(coordinator.start())
        cleanup.decisionJobActive = true
        workers.removeFirst().invoke()

        assertTrue(cancellationAccepted)
        assertEquals(1, jobsInsideFinish)
        assertFalse(cleanup.closedDuringDecisionJob)
        assertEquals(0, cleanup.owner.jobs())
        assertEquals(1, returned.closes)
        cleanup.assertClosedOnce()
        assertFalse(coordinator.hasPendingDecision())
    }

    @Test fun enqueueRefusalBalancesTheRealCleanupOwnerBeforeCancellationCleanup() {
        val cleanup = CleanupHarness()
        var cancellationAccepted = false
        var jobsDuringRefusal = -1
        lateinit var coordinator: ApprovalDecisionCoordinator<Submission>
        cleanup.decisionJobActive = true
        coordinator = ApprovalDecisionCoordinator(
            platform = object : ApprovalDecisionPlatform<Submission> {
                override fun finish(signedDecision: ByteArray) = Submission()
                override fun close(submission: Submission) { submission.closes++ }
                override fun busy(failure: Throwable): Boolean = false
            },
            enqueue = {
                jobsDuringRefusal = cleanup.owner.jobs()
                cleanup.owner.terminal()
                cancellationAccepted = coordinator.cancel()
                false
            },
            defer = { _, _ -> false },
            onPrepared = { false },
            onFailure = {},
            cleanup = cleanup.owner::requestCleanup,
            onJobStarted = cleanup.owner::jobStarted,
            onJobFinished = {
                cleanup.owner.jobFinished()
                cleanup.decisionJobActive = false
            },
        )

        assertTrue(coordinator.accept(byteArrayOf(1, 2, 3)))
        assertTrue(coordinator.start())

        assertTrue(cancellationAccepted)
        assertEquals(1, jobsDuringRefusal)
        assertFalse(cleanup.closedDuringDecisionJob)
        assertEquals(0, cleanup.owner.jobs())
        cleanup.assertClosedOnce()
        assertFalse(coordinator.hasPendingDecision())
        assertFalse(coordinator.cancel())
    }

    private class Fixture {
        val workers = ArrayDeque<() -> Unit>()
        val delayed = ArrayDeque<() -> Unit>()
        val platform = FakePlatform()
        val finish = platform.results
        val finishInputs = platform.inputs
        val decision = byteArrayOf(1, 2, 3)
        var prepared = 0
        var failures = 0
        var cleanups = 0

        val coordinator = ApprovalDecisionCoordinator(
            platform = platform,
            enqueue = { workers.addLast(it); true },
            defer = { _, work -> delayed.addLast(work); true },
            onPrepared = { prepared++; true },
            onFailure = { failures++ },
            cleanup = { cleanups++ },
        )

        fun runWorker() = workers.removeFirst().invoke()
        fun runDelayed() = delayed.removeFirst().invoke()
    }

    private class FakePlatform : ApprovalDecisionPlatform<Submission> {
        val results = ArrayDeque<() -> Submission>()
        val inputs = mutableListOf<List<Byte>>()

        override fun finish(signedDecision: ByteArray): Submission {
            inputs += signedDecision.toList()
            return results.removeFirst().invoke()
        }

        override fun close(submission: Submission) { submission.closes++ }
        override fun busy(failure: Throwable): Boolean = failure is OwnerBusy
    }

    private class CleanupHarness {
        val plan = CleanupPlan()
        val attempt = CleanupAttempt()
        private val operation = CleanupOperation()
        var decisionJobActive = false
        var closedDuringDecisionJob = false
        private var completions = 0

        val owner: ApprovalCleanupOwner<CleanupPlan, CleanupAttempt, Submission, CleanupOperation> =
            ApprovalCleanupOwner(
                platform = object : ApprovalCleanupPlatform<CleanupPlan, CleanupAttempt, Submission, CleanupOperation> {
                    override fun closeSubmission(submission: Submission) {
                        markCleanup()
                        submission.closes++
                    }
                    override fun retire(plan: CleanupPlan) {
                        markCleanup()
                        plan.retires++
                    }
                    override fun closeAttempt(attempt: CleanupAttempt) {
                        markCleanup()
                        attempt.closes++
                    }
                    override fun closePlan(plan: CleanupPlan) {
                        markCleanup()
                        plan.closes++
                    }
                    override fun operationQuiescent(operation: CleanupOperation): Boolean = true
                    override fun cancelPlan(plan: CleanupPlan) { plan.cancellations++ }
                    override fun planCancelled(plan: CleanupPlan): Boolean = false
                    override fun retirementBusy(failure: Throwable): Boolean = false
                },
                enqueue = { work -> work(); true },
                defer = { _, _ -> false },
                onComplete = { completions++ },
            )

        init {
            owner.bindPlan(plan)
            owner.bindAttempt(attempt)
            owner.bindOperation(operation)
        }

        fun assertClosedOnce() {
            assertEquals(1, plan.retires)
            assertEquals(1, attempt.closes)
            assertEquals(1, plan.closes)
            assertEquals(1, completions)
            assertTrue(owner.complete())
        }

        private fun markCleanup() {
            if (decisionJobActive) closedDuringDecisionJob = true
        }
    }

    private class CleanupPlan(var retires: Int = 0, var closes: Int = 0, var cancellations: Int = 0)
    private class CleanupAttempt(var closes: Int = 0)
    private class CleanupOperation
    private class Submission(var closes: Int = 0)
    private class OwnerBusy : RuntimeException()
    private class NativeFailure : RuntimeException()
}

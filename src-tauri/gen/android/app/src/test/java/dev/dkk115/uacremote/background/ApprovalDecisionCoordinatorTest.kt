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

    private class Submission(var closes: Int = 0)
    private class OwnerBusy : RuntimeException()
    private class NativeFailure : RuntimeException()
}

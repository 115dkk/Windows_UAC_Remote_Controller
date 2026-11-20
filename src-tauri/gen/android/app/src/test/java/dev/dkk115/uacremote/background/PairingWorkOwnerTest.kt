// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import dev.dkk115.uacremote.pairing.PairingScanRead
import dev.dkk115.uacremote.pairing.PairingScanStart
import dev.dkk115.uacremote.pairing.PairingScanTicket
import java.util.ArrayDeque
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PairingWorkOwnerTest {
    @Test fun acceptedInvitationStillStartsOnceAfterEightOtherCallsAreAdmitted() {
        val fixture = Fixture()
        fixture.accept()
        repeat(PolicyOwnerBounds.MAX_PENDING) {
            assertNull(fixture.lifecycle.admit())
            // These calls still await their main-thread replies after worker execution.
            fixture.workers.addLast {}
        }
        assertEquals(PolicyStatus.BUSY, fixture.lifecycle.admit())
        fixture.runMain()
        while (fixture.workers.isNotEmpty()) fixture.runWorker()
        fixture.owner.continueOnWorker()

        assertEquals(listOf(PairingScanRead.READ), fixture.reads)
        assertEquals(1, fixture.platform.starts)
        assertFalse(fixture.owner.reserveInvitation())
        assertEquals(PolicyOwnerBounds.MAX_PENDING, fixture.lifecycle.pendingCount())
    }

    @Test fun aDetachedReadCallbackDoesNotAuthorizeKeyCreation() {
        val fixture = Fixture()
        fixture.onRead = { throw NativeFailure() }
        fixture.accept()
        fixture.runMain()
        fixture.owner.continueOnWorker()
        fixture.owner.cleanupOnWorker(false)
        assertEquals(0, fixture.platform.starts)
        assertEquals(1, fixture.platform.scan.closes)
        assertEquals(1, fixture.releases)
    }

    @Test fun stoppingTheOwnerAfterHostCheckDoesNotCreateKeys() {
        val fixture = Fixture()
        fixture.accept()
        fixture.runMain()
        fixture.lifecycle.stop()
        fixture.runWorker()
        assertEquals(0, fixture.platform.starts)
        assertTrue(fixture.ticket.isCancelled())
        assertEquals(1, fixture.releases)
    }

    @Test fun rejectedInvitationNeverSchedulesTheCeremony() {
        for (result in listOf(PairingScanRead.INVALID, PairingScanRead.UNAVAILABLE)) {
            val fixture = Fixture()
            fixture.platform.read = result
            fixture.accept()
            fixture.runMain()
            fixture.owner.continueOnWorker()
            fixture.owner.cleanupOnWorker(false)
            assertEquals(listOf(result), fixture.reads)
            assertTrue(fixture.workers.isEmpty())
            assertEquals(0, fixture.platform.starts)
            assertEquals(1, fixture.releases)
        }
    }

    @Test fun fullWorkerQueueRetainsTheAcceptedContinuationForTheNextWorkerPass() {
        val fixture = Fixture()
        fixture.accept()
        fixture.rejectWorker = true
        fixture.runMain()
        assertEquals(0, fixture.platform.starts)
        assertFalse(fixture.ticket.isCancelled())
        fixture.rejectWorker = false
        fixture.owner.continueOnWorker()
        fixture.owner.continueOnWorker()
        assertEquals(1, fixture.platform.starts)
    }

    @Test fun hostGoneBeforeStartCancelsWithoutCreatingAKey() {
        val fixture = Fixture()
        fixture.accept()
        fixture.hostCurrent = false
        fixture.runMain()
        fixture.owner.cleanupOnWorker(false)
        assertEquals(listOf(PairingScanRead.UNAVAILABLE), fixture.reads)
        assertEquals(0, fixture.platform.starts)
        assertEquals(1, fixture.platform.scan.closes)
        assertEquals(1, fixture.releases)
        assertTrue(fixture.owner.complete())
    }

    @Test fun cancellationAfterHostCheckButBeforeStartClosesOnlyTheScan() {
        val fixture = Fixture()
        fixture.accept()
        fixture.runMain()
        fixture.owner.cancel()
        fixture.owner.cleanupOnWorker(false)
        fixture.runWorker()
        fixture.owner.cleanupOnWorker(false)
        assertEquals(0, fixture.platform.starts)
        assertEquals(1, fixture.platform.scan.closes)
        assertEquals(1, fixture.releases)
    }

    @Test fun cancellationDuringStartRetainsTheReturnedHandleUntilSettlement() {
        val fixture = Fixture()
        fixture.platform.onStart = { fixture.owner.cancel() }
        fixture.start()
        fixture.owner.cleanupOnWorker(false)
        assertEquals(0, fixture.platform.ceremony.closes)
        assertEquals(0, fixture.platform.scan.closes)
        assertFalse(fixture.owner.complete())
        fixture.platform.settled = true
        fixture.owner.cleanupOnWorker(false)
        fixture.owner.cleanupOnWorker(false)
        assertEquals(1, fixture.platform.ceremony.closes)
        assertEquals(1, fixture.platform.scan.closes)
        assertEquals(1, fixture.releases)
    }

    @Test fun cancellationWhileRunningSuppressesStatusAndWaitsForActualEnd() {
        val fixture = Fixture()
        fixture.start()
        fixture.owner.cancel()
        fixture.runPoll()
        assertTrue(fixture.statuses.isEmpty())
        assertEquals(0, fixture.platform.ceremony.closes)
        fixture.platform.settled = true
        fixture.runPoll()
        fixture.owner.cleanupOnWorker(false)
        assertEquals(1, fixture.platform.ceremony.closes)
        assertEquals(1, fixture.releases)
    }

    @Test fun failedCeremonyIsNotRestarted() {
        val fixture = Fixture()
        fixture.start()
        fixture.platform.status = Status.FAILED
        fixture.platform.settled = true
        fixture.runPoll()
        fixture.runMain()
        fixture.owner.continueOnWorker()
        fixture.owner.cleanupOnWorker(false)
        assertEquals(listOf(Status.FAILED), fixture.statuses)
        assertEquals(1, fixture.platform.starts)
        assertEquals(1, fixture.releases)
        assertFalse(fixture.owner.reserveInvitation())
    }

    @Test fun failedConstructorIsNotRestarted() {
        val fixture = Fixture()
        fixture.platform.failStart = true
        fixture.start()
        fixture.runMain()
        fixture.owner.continueOnWorker()
        fixture.owner.cleanupOnWorker(false)
        assertEquals(1, fixture.platform.starts)
        assertEquals(listOf(Status.UNAVAILABLE), fixture.statuses)
        assertEquals(1, fixture.platform.scan.closes)
        assertEquals(0, fixture.platform.ceremony.closes)
    }

    @Test fun unlockAndSecureLockAreCheckedAgainBeforeCreatingKeys() {
        for (secureLockMissing in listOf(false, true)) {
            val fixture = Fixture()
            fixture.accept()
            fixture.runMain()
            if (secureLockMissing) fixture.platform.secure = false else fixture.platform.unlocked = false
            fixture.runWorker()
            fixture.runMain()
            assertEquals(0, fixture.platform.starts)
            assertEquals(listOf(Status.UNAVAILABLE), fixture.statuses)
            assertTrue(fixture.ticket.isCancelled())
        }
    }

    @Test fun originalScanDeadlineIsRecheckedRatherThanRenewed() {
        val fixture = Fixture()
        fixture.accept()
        fixture.runMain()
        fixture.platform.expired = true
        fixture.runWorker()
        fixture.runMain()
        assertEquals(0, fixture.platform.starts)
        assertEquals(listOf(Status.UNAVAILABLE), fixture.statuses)
        assertTrue(fixture.ticket.isCancelled())
    }

    @Test fun settlementFailureRetainsBothHandlesAndUsesOnlyRemainingPollBudget() {
        val fixture = Fixture(maxPolls = 2)
        fixture.start()
        fixture.platform.failSettlement = true
        fixture.runPoll()
        fixture.owner.cleanupOnWorker(false)
        fixture.runPoll()
        repeat(3) { fixture.owner.cleanupOnWorker(false) }
        assertTrue(fixture.delayed.isEmpty())
        assertEquals(listOf(250L, 250L), fixture.delays)
        assertEquals(0, fixture.platform.scan.closes)
        assertEquals(0, fixture.platform.ceremony.closes)
        assertEquals(0, fixture.releases)
        fixture.platform.failSettlement = false
        fixture.platform.settled = true
        fixture.owner.cleanupOnWorker(false)
        assertEquals(1, fixture.releases)
        assertEquals(1, fixture.platform.starts)
    }

    @Test fun failedCloseRetainsTheExactHandleUntilExplicitRetry() {
        for (ceremonyClose in listOf(false, true)) {
            val fixture = Fixture()
            fixture.start()
            val failed = if (ceremonyClose) fixture.platform.ceremony else fixture.platform.scan
            val succeeded = if (ceremonyClose) fixture.platform.scan else fixture.platform.ceremony
            failed.failClose = true
            fixture.owner.cancel()
            fixture.platform.settled = true
            fixture.owner.cleanupOnWorker(false)
            fixture.owner.cleanupOnWorker(false)
            assertEquals(1, failed.closeAttempts)
            assertEquals(1, succeeded.closes)
            assertEquals(0, fixture.releases)
            assertFalse(fixture.owner.complete())
            failed.failClose = false
            fixture.owner.cleanupOnWorker(true)
            fixture.owner.cleanupOnWorker(true)
            assertEquals(2, failed.closeAttempts)
            assertEquals(1, failed.closes)
            assertEquals(1, succeeded.closes)
            assertEquals(1, fixture.releases)
        }
    }

    private class Fixture(maxPolls: Int = 1300) {
        val main = ArrayDeque<() -> Unit>()
        val workers = ArrayDeque<() -> Unit>()
        val delayed = ArrayDeque<() -> Unit>()
        val delays = mutableListOf<Long>()
        val reads = mutableListOf<PairingScanRead>()
        val statuses = mutableListOf<Status>()
        val ticket = PairingScanTicket()
        val platform = FakePlatform()
        val lifecycle = PolicyOwnerLifecycle().apply { start(); initialized(0, 0) }
        var hostCurrent = true
        var onRead: (PairingScanRead) -> Unit = { reads += it }
        var rejectWorker = false
        var releases = 0
        val owner = PairingWorkOwner(
            platform = platform,
            ticket = ticket,
            ready = { lifecycle.phase() == PolicyOwnerPhase.READY },
            post = { main.addLast(it); true },
            enqueue = { if (rejectWorker) false else { workers.addLast(it); true } },
            defer = { delay, work -> delays += delay; delayed.addLast(work); true },
            removeDeferred = { delayed.clear() },
            requestCleanup = {},
            released = { releases++ },
            unavailableStatus = { Status.UNAVAILABLE },
            maxPolls = maxPolls,
            pollIntervalMillis = 250L,
        )

        fun accept() {
            assertEquals(PairingScanStart.READY, owner.openOnWorker())
            assertTrue(owner.reserveInvitation())
            assertNull(lifecycle.admit())
            owner.readInvitationOnWorker("owned invitation", { hostCurrent }, { statuses += it }, onRead)
            lifecycle.release()
        }
        fun start() { accept(); runMain(); runWorker() }
        fun runMain() = main.removeFirst().invoke()
        fun runWorker() { workers.removeFirst().invoke(); owner.continueOnWorker(); owner.cleanupOnWorker(false) }
        fun runPoll() { delayed.removeFirst().invoke(); runWorker() }
    }

    private enum class Status { RUNNING, FAILED, UNAVAILABLE }
    private class Handle : AutoCloseable {
        var closeAttempts = 0
        var closes = 0
        var failClose = false
        override fun close() {
            closeAttempts++
            if (failClose) throw NativeFailure()
            closes++
        }
    }
    private class FakePlatform : PairingWorkPlatform<Handle, Handle, Status> {
        val scan = Handle()
        val ceremony = Handle()
        var starts = 0
        var settled = false
        var status = Status.RUNNING
        var read = PairingScanRead.READ
        var failSettlement = false
        var failStart = false
        var unlocked = true
        var secure = true
        var expired = false
        var onStart: () -> Unit = {}
        override fun beginScan(): Handle = scan
        override fun checkCurrent(scan: Handle) { if (expired) throw NativeFailure() }
        override fun acceptInvitation(scan: Handle, text: String): PairingScanRead = read
        override fun canCreateKeys(): Boolean = unlocked && secure
        override fun beginCeremony(scan: Handle): Handle {
            starts++
            if (failStart) throw NativeFailure()
            onStart()
            return ceremony
        }
        override fun cancelScan(scan: Handle) = Unit
        override fun cancelCeremony(ceremony: Handle) = Unit
        override fun isSettled(ceremony: Handle): Boolean {
            if (failSettlement) throw NativeFailure()
            return settled
        }
        override fun status(ceremony: Handle): Status = status
        override fun confirm(ceremony: Handle) = Unit
    }
    private class NativeFailure : RuntimeException()
}

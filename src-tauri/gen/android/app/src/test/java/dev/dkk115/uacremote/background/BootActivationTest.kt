// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import java.io.File
import java.io.IOException
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** JVM file/transaction fixtures. Not Android DE, reboot or hardware evidence. */
class BootActivationTest {
    @get:Rule val temporary = TemporaryFolder()

    private class Store(var value: BootActivationRecord) : BootActivationStore {
        var commits = 0
        var failCommit = false
        var afterCommit: (() -> Unit)? = null
        override fun read() = value
        override fun commit(expected: BootActivationRecord, desired: BootActivationRecord, beforeWrite: () -> Boolean): Boolean {
            commits++
            if (failCommit || value != expected || !beforeWrite()) return false
            value = desired
            afterCommit?.invoke()
            return true
        }
    }

    private fun io(store: BootActivationStore, legacy: BootComponentState = BootComponentState.DEFAULT,
        wake: BootComponentState = BootComponentState.DEFAULT) = BootRegistrationIo(store, { legacy }, { wake })

    @Test fun missingMigrationCommitsOnlyTheApprovedDefaultAndDisabledChoices() {
        for ((legacy, expected, record) in listOf(
            Triple(BootComponentState.DEFAULT, BootActivationState.ON, BootActivationRecord.ON),
            Triple(BootComponentState.DISABLED, BootActivationState.OFF, BootActivationRecord.OFF),
            Triple(BootComponentState.ENABLED, BootActivationState.LEGACY_MISSING, BootActivationRecord.MISSING),
            Triple(BootComponentState.UNAVAILABLE, BootActivationState.UNAVAILABLE, BootActivationRecord.MISSING),
        )) {
            val store = Store(BootActivationRecord.MISSING)
            assertEquals(expected, io(store, legacy).initialize { true }.state)
            assertEquals(record, store.value)
            assertEquals(if (record == BootActivationRecord.MISSING) 0 else 1, store.commits)
        }
    }

    @Test fun existingOffAndUnknownNeverBecomeOnDuringAutomaticInitialization() {
        for (legacy in BootComponentState.entries) {
            val off = Store(BootActivationRecord.OFF)
            assertEquals(BootActivationState.OFF, io(off, legacy).initialize { true }.state)
            assertEquals(0, off.commits)
            val unknown = Store(BootActivationRecord.UNAVAILABLE)
            assertEquals(BootActivationState.UNAVAILABLE, io(unknown, legacy).initialize { true }.state)
            assertEquals(0, unknown.commits)
        }
    }

    @Test fun initializationCannotPublishOnBeforeSuccessfulFreshCommit() {
        val failed = Store(BootActivationRecord.MISSING).apply { failCommit = true }
        assertEquals(BootRegistrationFailure.STORAGE, io(failed).initialize { true }.failure)
        assertEquals(BootActivationRecord.MISSING, failed.value)
        val cancelled = Store(BootActivationRecord.MISSING)
        assertEquals(BootActivationState.UNAVAILABLE, io(cancelled).initialize { false }.state)
        assertEquals(0, cancelled.commits)
    }

    @Test fun explicitLegacyStartCanResolveOnlyKnownAbsenceNotCorruptData() {
        val absent = Store(BootActivationRecord.MISSING)
        assertEquals(BootRegistrationResult(BootActivationState.ON),
            io(absent).mutate(BootActivationState.LEGACY_MISSING, BootRegistrationOperation.START) { true })
        val corrupt = Store(BootActivationRecord.UNAVAILABLE)
        assertEquals(BootRegistrationFailure.STORAGE,
            io(corrupt).mutate(BootActivationState.LEGACY_MISSING, BootRegistrationOperation.START) { true }.failure)
        assertEquals(BootActivationRecord.UNAVAILABLE, corrupt.value)
        assertEquals(BootRegistrationFailure.STORAGE,
            io(corrupt).mutate(BootActivationState.UNAVAILABLE, BootRegistrationOperation.START) { true }.failure)
    }

    @Test fun cancellationDuringCommitRecordsActualOnButNeverSuccessfulContinuation() {
        val fence = BootRegistrationFence()
        val ticket = fence.reserve(BootRegistrationOperation.START, 100)!!
        val store = Store(BootActivationRecord.OFF).apply { afterCommit = { ticket.cancel() } }
        val result = io(store).mutate(BootActivationState.OFF, BootRegistrationOperation.START) { ticket.mayContinue(101) }
        assertEquals(BootActivationState.ON, result.state)
        assertEquals(BootRegistrationFailure.CANCELLED, result.failure)
        assertEquals(BootActivationRecord.ON, store.value) // No invented rollback.
        assertSame(ticket, fence.current)
        assertNull(fence.reserve(BootRegistrationOperation.STOP, 102))
        assertTrue(fence.complete(ticket)) // Only actual completion releases it.
        assertNotNull(fence.reserve(BootRegistrationOperation.STOP, 103))
    }

    @Test fun delayedCommitStillUsesOriginalDeadlineAndFirstStorageError() {
        var now = 100L
        val ticket = BootRegistrationFence().reserve(BootRegistrationOperation.START, now)!!
        val store = Store(BootActivationRecord.OFF).apply { afterCommit = { now = 5_100 } }
        val result = io(store).mutate(BootActivationState.OFF, BootRegistrationOperation.START) { ticket.mayContinue(now) }
        assertEquals(BootRegistrationFailure.CANCELLED, result.failure)
        assertEquals(BootActivationState.ON, result.state)
        val failed = Store(BootActivationRecord.ON).apply { failCommit = true }
        assertEquals(BootRegistrationFailure.STORAGE,
            io(failed, wake = BootComponentState.UNAVAILABLE).mutate(BootActivationState.ON, BootRegistrationOperation.STOP) { true }.failure)
    }

    @Test fun disabledWakeIsNeverRepairedAndDoesNotUndoTheCommittedStop() {
        val store = Store(BootActivationRecord.ON)
        val result = io(store, wake = BootComponentState.DISABLED).mutate(BootActivationState.ON, BootRegistrationOperation.STOP) { true }
        assertEquals(BootRegistrationFailure.COMPONENT, result.failure)
        assertEquals(BootActivationState.OFF, result.state)
        assertEquals(BootActivationRecord.OFF, store.value)
    }

    @Test fun downwardStopPrecedesFailedPersistenceAndNeitherFailureCanBecomeSuccess() {
        val order = ArrayList<String>()
        val completion = BootStopCompletion.attempt { order.add("native-stop"); NativeStopObservation.MATCHED_SERVICE }
        val failed = Store(BootActivationRecord.ON).apply { failCommit = true }
        order.add("persist-off")
        val result = io(failed).mutate(BootActivationState.ON, BootRegistrationOperation.STOP) { true }
        assertEquals(listOf("native-stop", "persist-off"), order)
        assertEquals(ServiceControlResult.UNAVAILABLE, completion.finish(result, 100, 101))
        val goodOff = BootRegistrationResult(BootActivationState.OFF)
        val nativeFailure = BootStopCompletion.attempt { throw IOException("synthetic native stop failure") }
        assertEquals(ServiceControlResult.UNAVAILABLE, nativeFailure.finish(goodOff, 100, 101))
        assertEquals(ServiceControlResult.UNAVAILABLE, completion.finish(goodOff, 100, 5_100))
        assertEquals(ServiceControlResult.REQUESTED, completion.finish(goodOff, 100, 101))
    }

    @Test fun retiredOrTimedOutTicketCannotReleaseOrReplaceItsOwnedWriter() {
        val fence = BootRegistrationFence()
        val first = fence.reserve(BootRegistrationOperation.START, 100)!!
        fence.cancelStart() // Same transition used for Activity retirement/STOP.
        assertFalse(first.mayContinue(101))
        assertNull(fence.reserve(BootRegistrationOperation.START, 102))
        assertTrue(fence.complete(first))
        val second = fence.reserve(BootRegistrationOperation.STOP, 103)!!
        assertFalse(fence.complete(first))
        assertSame(second, fence.current)
        assertFalse(second.mayContinue(5_103))
        assertFalse(second.mayContinue(102))
        assertTrue(fence.complete(second))
        val exhausted = BootRegistrationFence(Long.MAX_VALUE)
        val last = exhausted.reserve(BootRegistrationOperation.START, 0)!!
        assertEquals(Long.MAX_VALUE, last.generation)
        assertTrue(exhausted.complete(last))
        assertNull(exhausted.reserve(BootRegistrationOperation.START, 1))
    }

    @Test fun fixedFileCommitsAndReopensBothChoicesWithoutASecondNamespace() {
        val directory = temporary.newFolder()
        var syncs = 0
        fun open() = BootActivationFile(directory) { syncs++ }
        assertEquals(BootActivationRecord.MISSING, open().read())
        assertTrue(open().commit(BootActivationRecord.MISSING, BootActivationRecord.ON) { true })
        assertEquals(BootActivationRecord.ON, open().read())
        assertTrue(open().commit(BootActivationRecord.ON, BootActivationRecord.OFF) { true })
        assertEquals(BootActivationRecord.OFF, open().read())
        assertEquals(4, syncs)
        assertEquals(listOf("controller-boot-activation-v1"), directory.list()?.toList())
    }

    @Test fun unknownRecordAndInterruptedReplacementCannotDefaultOrBeOverwritten() {
        for (bytes in listOf(byteArrayOf(), "v2:on\n".toByteArray(), "v1:on\nextra".toByteArray(), ByteArray(4096))) {
            val directory = temporary.newFolder()
            File(directory, "controller-boot-activation-v1").writeBytes(bytes)
            val store = BootActivationFile(directory) { }
            assertEquals(BootActivationRecord.UNAVAILABLE, store.read())
            assertFalse(store.commit(BootActivationRecord.MISSING, BootActivationRecord.ON) { true })
            assertArrayEquals(bytes, File(directory, "controller-boot-activation-v1").readBytes())
        }
        val directory = temporary.newFolder()
        val normal = BootActivationFile(directory) { }
        assertTrue(normal.commit(BootActivationRecord.MISSING, BootActivationRecord.OFF) { true })
        File(directory, "controller-boot-activation-v1.pending").writeText("v1:on\n")
        assertEquals(BootActivationRecord.UNAVAILABLE, normal.read())
        assertFalse(normal.commit(BootActivationRecord.OFF, BootActivationRecord.ON) { true })
    }

    @Test fun aFreshFenceAfterTheActualPreconditionReadPreventsAnyLateFileMutation() {
        val directory = temporary.newFolder()
        var nativeSyncs = 0
        val store = BootActivationFile(directory) { nativeSyncs++ }
        var fenceCalls = 0
        assertFalse(store.commit(BootActivationRecord.MISSING, BootActivationRecord.ON) { fenceCalls++; false })
        assertEquals(1, fenceCalls)
        assertEquals(0, nativeSyncs)
        assertEquals(BootActivationRecord.MISSING, store.read())
        assertTrue(directory.list().isNullOrEmpty())
    }

    @Test fun failedDirectorySyncRetainsUncertaintyWithoutRollbackOrRetry() {
        val directory = temporary.newFolder()
        val failing = BootActivationFile(directory) { throw IOException("synthetic sync failure") }
        assertFalse(failing.commit(BootActivationRecord.MISSING, BootActivationRecord.ON) { true })
        assertEquals(BootActivationRecord.UNAVAILABLE, BootActivationFile(directory) { }.read())
        assertTrue(File(directory, "controller-boot-activation-v1.pending").exists())
        assertFalse(failing.commit(BootActivationRecord.MISSING, BootActivationRecord.OFF) { true })
    }

    @Test fun readableOffAfterFailedRenameSyncRequiresFreshCheckedSyncOnSameStateRetry() {
        val directory = temporary.newFolder()
        var calls = 0
        val failedAfterRename = BootActivationFile(directory) {
            calls++
            if (calls == 2) throw IOException("synthetic post-rename sync failure")
        }
        assertFalse(failedAfterRename.commit(BootActivationRecord.MISSING, BootActivationRecord.OFF) { true })
        assertEquals(BootActivationRecord.OFF, BootActivationFile(directory) { }.read())
        assertFalse(File(directory, "controller-boot-activation-v1.pending").exists())
        var retrySyncs = 0
        val stillFailing = BootActivationFile(directory) { retrySyncs++; throw IOException("synthetic retry sync failure") }
        assertFalse(stillFailing.commit(BootActivationRecord.OFF, BootActivationRecord.OFF) { true })
        assertEquals(1, retrySyncs)
        val recovered = BootActivationFile(directory) { retrySyncs++ }
        assertTrue(recovered.commit(BootActivationRecord.OFF, BootActivationRecord.OFF) { true })
        assertEquals(2, retrySyncs)
        assertEquals(BootActivationRecord.OFF, recovered.read())
    }
}

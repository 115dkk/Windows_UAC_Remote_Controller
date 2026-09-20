// SPDX-License-Identifier: GPL-2.0-or-later

package dev.dkk115.uacremote.background

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Synthetic metadata only. No Application, Settings, clock, user, or filesystem API is invoked. */
class NativeEnvironmentRulesTest {
    private fun local() = LocalEnvironmentObservation(
        epochDay = 4, isoWeekday = 1, hour = 10, minute = 0,
        zoneId = "Asia/Seoul", offsetSeconds = 32_400,
    )

    private fun read() = NativeEnvironmentRead(
        startedNanos = 1_000_000, sampledNanos = 1_500_001, completedNanos = 2_000_000,
        bootBefore = 7, bootAfter = 7, localBefore = local(), localAfter = local(),
        storageBefore = CredentialStorageState.AVAILABLE,
        storageAfter = CredentialStorageState.AVAILABLE,
    )

    private fun <T> value(outcome: NativeEnvironmentOutcome<T>): T = when (outcome) {
        is NativeEnvironmentOutcome.Value -> outcome.value
        is NativeEnvironmentOutcome.Failure -> throw AssertionError("Expected synthetic value, got ${outcome.error}")
    }

    private fun error(outcome: NativeEnvironmentOutcome<*>): NativeEnvironmentError = when (outcome) {
        is NativeEnvironmentOutcome.Failure -> outcome.error
        is NativeEnvironmentOutcome.Value -> throw AssertionError("Expected a fixed synthetic failure")
    }

    @Test fun coherentSnapshotKeepsBothNativeCountersAndExactFloorUnitMapping() {
        val snapshot = value(NativeEnvironmentRules.snapshot(read()))
        assertEquals(7, snapshot.bootCount)
        assertEquals(1_500_001L, snapshot.elapsedRealtimeNanos)
        assertEquals(1L, snapshot.elapsedRealtimeMillis)
        assertEquals(2_000_000L, snapshot.readCompletedElapsedRealtimeNanos)
        assertEquals(1_000_000L, snapshot.readSpanNanos)
        assertEquals(0, snapshot.weekdayMondayZero)
        assertEquals(600, snapshot.minuteOfDay)
        assertEquals(CredentialStorageState.AVAILABLE, snapshot.credentialStorage)
    }

    @Test fun zeroBootAndEqualNonnegativeClockReadsAreValidNotErrorDefaults() {
        val snapshot = value(NativeEnvironmentRules.snapshot(read().copy(
            bootBefore = 0, bootAfter = 0, startedNanos = 0, sampledNanos = 0, completedNanos = 0,
        )))
        assertEquals(0, snapshot.bootCount)
        assertEquals(0L, snapshot.elapsedRealtimeNanos)
        assertEquals(0L, snapshot.elapsedRealtimeMillis)
        assertEquals(0L, snapshot.readSpanNanos)
        val failure = NativeEnvironmentOutcome.Failure(NativeEnvironmentError.BOOT_COUNT_UNAVAILABLE)
        assertEquals(NativeEnvironmentError.BOOT_COUNT_UNAVAILABLE, error(failure))
        assertFalse(failure.toString().contains("Value"))
    }

    @Test fun weekdayAndMinuteMappingsHaveClosedNativeRanges() {
        assertEquals((0..6).toList(), (1..7).map(NativeEnvironmentRules::weekdayMondayZero))
        for (invalid in listOf(Int.MIN_VALUE, -1, 0, 8, Int.MAX_VALUE)) {
            assertNull(NativeEnvironmentRules.weekdayMondayZero(invalid))
        }
        assertEquals(0, NativeEnvironmentRules.minuteOfDay(0, 0))
        assertEquals(1_439, NativeEnvironmentRules.minuteOfDay(23, 59))
        for ((hour, minute) in listOf(-1 to 0, 24 to 0, 0 to -1, 0 to 60, Int.MAX_VALUE to Int.MAX_VALUE)) {
            assertNull(NativeEnvironmentRules.minuteOfDay(hour, minute))
        }
        assertEquals(0L, NativeEnvironmentRules.elapsedMillis(999_999))
        assertEquals(1L, NativeEnvironmentRules.elapsedMillis(1_000_000))
        assertEquals(Long.MAX_VALUE / 1_000_000, NativeEnvironmentRules.elapsedMillis(Long.MAX_VALUE))
        assertNull(NativeEnvironmentRules.elapsedMillis(-1))
    }

    @Test fun negativeBootFailsAndChangedBootCannotProduceASnapshot() {
        for (invalid in listOf(read().copy(bootBefore = -1), read().copy(bootAfter = Int.MIN_VALUE))) {
            assertEquals(NativeEnvironmentError.INVALID_BOOT_COUNT, error(NativeEnvironmentRules.snapshot(invalid)))
        }
        assertEquals(NativeEnvironmentError.UNSTABLE_OBSERVATION,
            error(NativeEnvironmentRules.snapshot(read().copy(bootAfter = 8))))
        assertEquals(Int.MAX_VALUE, value(NativeEnvironmentRules.snapshot(read().copy(
            bootBefore = Int.MAX_VALUE, bootAfter = Int.MAX_VALUE,
        ))).bootCount)
    }

    @Test fun negativeRegressingOrOutOfBracketElapsedTimesAreRejected() {
        val invalid = listOf(
            read().copy(startedNanos = -1), read().copy(startedNanos = Long.MIN_VALUE),
            read().copy(sampledNanos = -1), read().copy(sampledNanos = 999_999),
            read().copy(completedNanos = -1), read().copy(completedNanos = 1_500_000),
        )
        for (sample in invalid) {
            assertEquals(NativeEnvironmentError.INVALID_ELAPSED_TIME,
                error(NativeEnvironmentRules.snapshot(sample)))
        }
    }

    @Test fun boundedReadSpanIncludesBoundaryWithoutSignedOverflow() {
        val span = NativeEnvironmentRules.MAX_READ_SPAN_NANOS
        val nearLimit = read().copy(
            startedNanos = Long.MAX_VALUE - span,
            sampledNanos = Long.MAX_VALUE - 1,
            completedNanos = Long.MAX_VALUE,
        )
        assertEquals(span, value(NativeEnvironmentRules.snapshot(nearLimit)).readSpanNanos)
        for (completed in listOf(span + 1, Long.MAX_VALUE)) {
            val tooSlow = read().copy(startedNanos = 0, sampledNanos = 1, completedNanos = completed)
            assertEquals(NativeEnvironmentError.READ_SPAN_TOO_LONG,
                error(NativeEnvironmentRules.snapshot(tooSlow)))
        }
    }

    @Test fun dateMinuteZoneAndOffsetChangesRequireANewObservation() {
        for (changed in listOf(
            local().copy(epochDay = 11), local().copy(isoWeekday = 2), local().copy(hour = 11),
            local().copy(minute = 1), local().copy(zoneId = "Etc/UTC"), local().copy(offsetSeconds = 0),
        )) {
            assertEquals(NativeEnvironmentError.UNSTABLE_OBSERVATION,
                error(NativeEnvironmentRules.snapshot(read().copy(localAfter = changed))))
        }
    }

    @Test fun invalidLocalShapesNeverBecomeDefaultMondayOrMidnight() {
        for (invalid in listOf(
            local().copy(isoWeekday = 0), local().copy(isoWeekday = 8),
            local().copy(hour = -1), local().copy(hour = 24),
            local().copy(minute = -1), local().copy(minute = 60),
            local().copy(zoneId = ""), local().copy(zoneId = "x".repeat(256)),
            local().copy(offsetSeconds = -64_801), local().copy(offsetSeconds = 64_801),
        )) {
            assertEquals(NativeEnvironmentError.INVALID_LOCAL_TIME,
                error(NativeEnvironmentRules.snapshot(read().copy(localBefore = invalid, localAfter = invalid))))
        }
    }

    @Test fun credentialStorageAvailabilityIsSeparateFromAuthenticationAndReadFailure() {
        val locked = value(NativeEnvironmentRules.snapshot(read().copy(
            storageBefore = CredentialStorageState.LOCKED, storageAfter = CredentialStorageState.LOCKED,
        )))
        assertEquals(CredentialStorageState.LOCKED, locked.credentialStorage)
        assertEquals(NativeEnvironmentError.UNSTABLE_OBSERVATION,
            error(NativeEnvironmentRules.snapshot(read().copy(storageAfter = CredentialStorageState.LOCKED))))
        assertEquals(NativeEnvironmentError.CREDENTIAL_STORAGE_UNAVAILABLE,
            error(NativeEnvironmentOutcome.Failure(NativeEnvironmentError.CREDENTIAL_STORAGE_UNAVAILABLE)))
    }

    @Test fun onlyObservedRacesAndSlowReadsAreRetryableWithinThreeAttempts() {
        assertEquals(3, NativeEnvironmentRules.MAX_READ_ATTEMPTS)
        assertEquals(100_000_000L, NativeEnvironmentRules.MAX_READ_SPAN_NANOS)
        for (failure in NativeEnvironmentError.values()) {
            val expected = failure == NativeEnvironmentError.UNSTABLE_OBSERVATION ||
                failure == NativeEnvironmentError.READ_SPAN_TOO_LONG
            assertEquals(expected, NativeEnvironmentRules.mayRetry(failure))
        }
    }

    @Test fun directoryShapeRejectsLinksAndNonDirectoriesWithoutRepair() {
        assertNull(NativeEnvironmentRules.directoryEntryError(isDirectory = true, isSymbolicLink = false))
        for ((directory, link) in listOf(true to true, false to false, false to true)) {
            assertEquals(NativeEnvironmentError.DIRECTORY_UNSAFE_ENTRY,
                NativeEnvironmentRules.directoryEntryError(directory, link))
        }
        assertEquals("controller-state", NativeEnvironmentRules.DIRECTORY_NAME)
    }

    @Test fun debugAndFailuresDoNotPrintNativePathsOrObservationValues() {
        val directory = NativeStateDirectory("/synthetic/private/controller-state")
        val snapshot = value(NativeEnvironmentRules.snapshot(read()))
        val visible = "$directory $snapshot ${read()} ${local()} ${NativeEnvironmentOutcome.Value(directory)}"
        assertFalse(visible.contains("/synthetic/private"))
        assertFalse(visible.contains("Asia/Seoul"))
        assertFalse(visible.contains("1500001"))
        assertTrue(NativeEnvironmentOutcome.Failure(NativeEnvironmentError.BOOT_COUNT_UNAVAILABLE)
            .toString().contains("BOOT_COUNT_UNAVAILABLE"))
    }
}

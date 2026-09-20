// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertEquals
import org.junit.Test

/** Synthetic clock numbers only; no SystemClock/Settings/Android clock reads. */
class NativePresentationClockRulesTest {
    @Test fun OnlyKnownLiveNonfaultedUnwarmedClockRequestsRefresh() {
        assertEquals(PresentationClockAvailability.READY, PresentationClockRules.availability(true, true, true, false, false))
        assertEquals(PresentationClockAvailability.REFRESH_REQUIRED, PresentationClockRules.availability(true, true, false, false, false))
        assertEquals(PresentationClockAvailability.UNAVAILABLE, PresentationClockRules.availability(false, true, false, false, false))
        assertEquals(PresentationClockAvailability.UNAVAILABLE, PresentationClockRules.availability(true, false, false, false, false))
        assertEquals(PresentationClockAvailability.UNAVAILABLE, PresentationClockRules.availability(true, true, false, true, false))
        assertEquals(PresentationClockAvailability.UNAVAILABLE, PresentationClockRules.availability(true, true, false, false, true))
        assertEquals(PresentationClockAvailability.UNAVAILABLE, PresentationClockRules.availability(true, true, true, false, true))
    }
    @Test fun equalCounterAndBootOriginAreNotInventedErrors() {
        assertTrue(PresentationClockRules.valid(0, 0, 0, 0))
        assertTrue(PresentationClockRules.valid(12, 12, 90, 90))
    }
    @Test fun negativeOrRegressingClockNeverFallsBackToZero() {
        assertFalse(PresentationClockRules.valid(-1, 0, 1, 1))
        assertFalse(PresentationClockRules.valid(10, 9, 1, 1))
        assertFalse(PresentationClockRules.valid(0, 1, -1, 0))
        assertFalse(PresentationClockRules.valid(0, 1, 10, 9))
    }
    @Test fun nativeReadSpanHasAnInclusive100msBound() {
        assertTrue(PresentationClockRules.valid(20, 100_000_020, 1000, 1100))
        assertFalse(PresentationClockRules.valid(20, 100_000_021, 1000, 1100))
    }
    @Test fun MillisecondRoundingIsAllowedButClockJumpIsNot() {
        assertTrue(PresentationClockRules.valid(0, 900_000, 1000, 1001))
        assertTrue(PresentationClockRules.valid(0, 1_100_000, 1000, 1000))
        assertFalse(PresentationClockRules.valid(0, 1_100_000, 1000, 1010))
        assertFalse(PresentationClockRules.valid(0, 20_000_000, 1000, 1000))
    }
    @Test fun ExtremeWallDeltaRejectsBeforeNanosecondMultiplication() {
        assertFalse(PresentationClockRules.valid(0, 1, 0, Long.MAX_VALUE))
    }
    @Test fun PreviousObservationRejectsDiscontinuityAndAllowsRounding() {
        assertTrue(PresentationClockRules.consistentPrevious(5_000_000_000, 6000, 4_000_000_000, 5000))
        assertTrue(PresentationClockRules.consistentPrevious(5_000_000_000, 6002, 4_000_000_000, 5000))
        assertFalse(PresentationClockRules.consistentPrevious(5_000_000_000, 6003, 4_000_000_000, 5000))
        assertFalse(PresentationClockRules.consistentPrevious(3_999_999_999, 5000, 4_000_000_000, 5000))
        assertFalse(PresentationClockRules.consistentPrevious(5_000_000_000, 4999, 4_000_000_000, 5000))
    }
}

// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ApprovalBusyRetryTest {
    @Test fun aBusyOwnerIsWaitedForBrieflyAtFirstAndThenLonger() {
        val retry = ApprovalBusyRetry()
        val delays = generateSequence { retry.next() }.toList()
        assertEquals(listOf(25L, 50L, 100L, 200L, 400L, 400L), delays)
        assertEquals(delays, delays.sorted())
    }

    @Test fun theBudgetEndsAndStaysEnded() {
        val retry = ApprovalBusyRetry()
        repeat(ApprovalBusyRetry.DELAYS_MILLIS.size) { assertTrue(retry.next() != null) }
        repeat(8) { assertNull(retry.next()) }
        assertEquals(ApprovalBusyRetry.DELAYS_MILLIS.size, retry.waits())
        // Well inside one request's 110 second lease, so the lease decides.
        assertTrue(ApprovalBusyRetry.DELAYS_MILLIS.sum() < 5_000L)
    }

    @Test fun eachSessionHasItsOwnBudget() {
        val first = ApprovalBusyRetry()
        repeat(ApprovalBusyRetry.DELAYS_MILLIS.size) { first.next() }
        assertNull(first.next())
        assertEquals(25L, ApprovalBusyRetry().next())
    }
}

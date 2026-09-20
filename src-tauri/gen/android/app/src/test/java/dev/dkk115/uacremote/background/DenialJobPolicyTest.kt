// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** Synthetic identities/cursors only; no generated scope/session or OS observation. */
class DenialJobPolicyTest {
    @Test fun actualSlotRetirementWakesOtherWaiterOnceWithoutAnExternalEvent() {
        val signingA = Any(); val waitingB = Any()
        val pending = LinkedHashSet<Any>()
        if (DenialCapacityProgress.retired(false, false)) pending.addAll(DenialCapacityProgress.others(signingA, listOf(signingA, waitingB)))
        assertTrue(pending.isEmpty())
        if (DenialCapacityProgress.retired(false, true)) pending.addAll(DenialCapacityProgress.others(signingA, listOf(signingA, waitingB)))
        assertEquals(listOf(waitingB), pending.toList())
        pending.clear()
        if (DenialCapacityProgress.retired(true, true)) pending.addAll(DenialCapacityProgress.others(signingA, listOf(signingA, waitingB)))
        assertTrue(pending.isEmpty()) // Re-observing Prepared never self-polls.
    }
    @Test fun delayedPreparedReplyRequiresCurrentUncancelledJobAndLiveScope() {
        assertTrue(DenialReplyPolicy.mayReportPrepared(true, false, false, true))
        assertFalse(DenialReplyPolicy.mayReportPrepared(false, false, false, true))
        assertFalse(DenialReplyPolicy.mayReportPrepared(true, true, false, true))
        assertFalse(DenialReplyPolicy.mayReportPrepared(true, false, true, true))
        assertFalse(DenialReplyPolicy.mayReportPrepared(true, false, false, false))
    }
    @Test fun sameRequestCannotReplaceItsReservedOwnerAcrossBusyWaits() {
        val book = DenialFenceBook<Any>()
        val original = Any(); val later = Any()
        assertTrue(book.add("synthetic-request", original))
        assertFalse(book.add("synthetic-request", later))
        assertSame(original, book.get("synthetic-request"))
        assertFalse(book.remove("synthetic-request", later))
        assertSame(original, book.get("synthetic-request"))
        assertTrue(book.remove("synthetic-request", original))
        assertNull(book.get("synthetic-request"))
    }
    @Test fun boundsAndOtherRequestsAreIndependent() {
        val book = DenialFenceBook<Any>()
        val values = List(32) { Any() }
        values.forEachIndexed { index, value -> assertTrue(book.add("synthetic-$index", value)) }
        assertFalse(book.add("overflow", Any()))
        assertEquals(32, book.snapshot().size)
        assertTrue(book.remove("synthetic-4", values[4]))
        assertSame(values[5], book.get("synthetic-5"))
        assertTrue(book.add("new-synthetic", Any()))
    }
    @Test fun cancellationAloneOrRetirementAloneCannotAcknowledgeDrain() {
        assertTrue(DenialDrainCompletion.retired(true, 0, true, true, true, true))
        assertFalse(DenialDrainCompletion.retired(false, 0, true, true, true, true))
        assertFalse(DenialDrainCompletion.retired(true, 1, true, true, true, true))
        assertFalse(DenialDrainCompletion.retired(true, 0, false, true, true, true))
        assertFalse(DenialDrainCompletion.retired(true, 0, true, false, true, true))
        assertFalse(DenialDrainCompletion.retired(true, 0, true, true, false, true))
        assertFalse(DenialDrainCompletion.retired(true, 0, true, true, true, false))
    }
    private class Handle(var failures: Int = 0) : AutoCloseable {
        var closes = 0
        override fun close() { closes += 1; if (failures-- > 0) throw IllegalStateException("synthetic close failure") }
    }
    @Test fun failedExactCloseIsRetainedAndNotRetriedByOrdinaryCalls() {
        val cursor = DenialCloseCursor(); val handle = Handle(1)
        try { cursor.closeOrRetain(handle) } catch (_: IllegalStateException) { }
        assertEquals(1, handle.closes); assertFalse(cursor.complete())
        try { cursor.closeOrRetain(handle) } catch (_: IllegalStateException) { }
        assertEquals(1, handle.closes)
        assertTrue(cursor.retryOnce()); assertEquals(2, handle.closes)
        assertTrue(cursor.retryOnce()); assertEquals(2, handle.closes)
    }
    @Test fun partialCloseProgressNeverRepeatsSuccessfulHandles() {
        val cursor = DenialCloseCursor(); val first = Handle(1); val second = Handle(2)
        for (value in listOf(first, second)) try { cursor.closeOrRetain(value) } catch (_: IllegalStateException) { }
        assertFalse(cursor.retryOnce()); assertEquals(2, first.closes); assertEquals(2, second.closes)
        assertTrue(cursor.retryOnce()); assertEquals(2, first.closes); assertEquals(3, second.closes)
    }
    @Test fun excessiveUnknownFailedHandlesNeverBecomeCleanupComplete() {
        val cursor = DenialCloseCursor(1)
        for (value in listOf(Handle(1), Handle(1))) try { cursor.closeOrRetain(value) } catch (_: IllegalStateException) { }
        assertFalse(cursor.retryOnce()); assertFalse(cursor.complete())
    }
}

// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import java.util.concurrent.atomic.AtomicBoolean
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Real existing exact-close cursor with synthetic AutoCloseable wrappers only. */
class CreationArgumentCleanupPolicyTest {
    private class Argument(private val active: AtomicBoolean) : AutoCloseable {
        var calls = 0
        var fails = true
        var retryObservedGate = false
        override fun close() {
            calls += 1
            if (calls > 1) retryObservedGate = active.get()
            if (fails) throw IllegalStateException("Synthetic close failure")
        }
    }

    @Test fun automaticReadinessNeverRetriesAFailedGeneratedHandle() {
        val active = AtomicBoolean(false)
        val cursor = DenialCloseCursor(2)
        val argument = Argument(active)
        try { cursor.closeOrRetain(argument) } catch (_: IllegalStateException) { }
        assertEquals(1, argument.calls)
        repeat(5) { assertFalse(CreationArgumentCleanupPolicy.ready(active, cursor)) }
        assertEquals(1, argument.calls)
        // A failed EXPLICIT retry is one attempt, preserving the failed cursor.
        assertFalse(CreationArgumentCleanupPolicy.retryExplicitly(active, cursor))
        assertEquals(2, argument.calls)
        assertTrue(argument.retryObservedGate)
        assertFalse(active.get())
        repeat(5) { assertFalse(CreationArgumentCleanupPolicy.ready(active, cursor)) }
        assertEquals(2, argument.calls)
        argument.fails = false
        assertTrue(CreationArgumentCleanupPolicy.retryExplicitly(active, cursor))
        assertEquals(3, argument.calls)
        assertTrue(CreationArgumentCleanupPolicy.ready(active, cursor))
    }

    @Test fun activeNativeCreationCannotBeRetriedOrReportedReady() {
        val active = AtomicBoolean(false)
        val cursor = DenialCloseCursor(2)
        val argument = Argument(active)
        try { cursor.closeOrRetain(argument) } catch (_: IllegalStateException) { }
        argument.fails = false
        active.set(true)
        assertFalse(CreationArgumentCleanupPolicy.retryExplicitly(active, cursor))
        assertFalse(CreationArgumentCleanupPolicy.ready(active, cursor))
        assertEquals(1, argument.calls)
        assertTrue(active.get())
        active.set(false)
        assertTrue(CreationArgumentCleanupPolicy.retryExplicitly(active, cursor))
        assertEquals(2, argument.calls)
    }
}

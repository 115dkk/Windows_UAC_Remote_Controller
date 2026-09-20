// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import org.junit.Assert.*
import org.junit.Test

/** Synthetic ownership identities only. No intents, native handles or decisions. */
class NotificationRefreshQueueTest {
    @Test fun oneOriginalTicketPerRequestAndExplicitCapacity() {
        val queue = NotificationRefreshQueue<Any>(2)
        val original = Any()
        assertTrue(queue.offer("request-a", original))
        assertFalse(queue.offer("request-a", Any()))
        assertTrue(queue.offer("request-b", Any()))
        assertFalse(queue.offer("request-c", Any()))
        val ticket = queue.take()!!
        assertSame(original, ticket.value)
        assertSame(original, queue.finish(ticket, false))
        assertTrue(queue.offer("request-c", Any()))
    }

    @Test fun busyRequiresNewProgressAndCannotSpinAfterSecondAttempt() {
        val queue = NotificationRefreshQueue<Any>()
        val original = Any()
        queue.offer("request-a", original)
        val first = queue.take()!!
        queue.attempted(first)
        assertNull(queue.finish(first, true))
        assertFalse(queue.eligible())
        assertNull(queue.take())
        queue.progress()
        val second = queue.take()!!
        assertSame(first, second)
        queue.attempted(second)
        assertSame(original, queue.finish(second, true))
        queue.progress()
        assertNull(queue.take())
    }

    @Test fun queueRejectionNeedsNoNewTicketAndStopRetainsInFlightOwnership() {
        val queue = NotificationRefreshQueue<Any>()
        val running = Any(); val waiting = Any()
        queue.offer("running", running); queue.offer("waiting", waiting)
        assertTrue(queue.eligible()) // Failed executor insertion has not taken it.
        val ticket = queue.take()!!
        assertEquals(listOf(waiting), queue.stop())
        assertNull(queue.take())
        assertFalse(queue.offer("replacement", Any()))
        assertSame(running, queue.finish(ticket, true)) // Actual call ended now.
        assertTrue(queue.stop().isEmpty())
    }

    @Test fun progressDuringNativeCallDoesNotMintParallelAttempts() {
        val queue = NotificationRefreshQueue<Any>()
        queue.offer("request", Any())
        val ticket = queue.take()!!
        queue.progress()
        assertFalse(queue.eligible())
        assertNull(queue.take())
        assertNull(queue.finish(ticket, true))
        assertNull(queue.take())
    }

    @Test fun waitingForRealActionCleanupDoesNotSpendNativeCallBudget() {
        val queue = NotificationRefreshQueue<Any>()
        val original = Any()
        queue.offer("request", original)
        repeat(3) {
            val ticket = queue.take()!!
            assertNull(queue.finish(ticket, true)) // No native call made.
            assertNull(queue.take())
            queue.progress() // Actual action/native cleanup progress.
        }
        repeat(2) { index ->
            val ticket = queue.take()!!
            queue.attempted(ticket)
            val released = queue.finish(ticket, true)
            if (index == 0) { assertNull(released); queue.progress() }
            else assertSame(original, released)
        }
        assertNull(queue.take())
    }
}

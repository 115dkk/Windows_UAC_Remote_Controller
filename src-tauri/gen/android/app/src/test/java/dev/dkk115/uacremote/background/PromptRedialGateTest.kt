// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Pure spacing only; no handler, dial or peer. */
class PromptRedialGateTest {
    @Test fun firstSessionEndRunsAtOnce() {
        assertEquals(0L, PromptRedialGate(1_000L).request(5_000L))
    }

    @Test fun triggersWhileScheduledJoinTheOneRun() {
        val gate = PromptRedialGate(1_000L)
        assertEquals(0L, gate.request(5_000L))
        repeat(10) { assertNull(gate.request(5_000L + it)) }
        gate.ran(5_010L)
        assertEquals(1_000L, gate.request(5_010L))
    }

    @Test fun aTriggerInsideTheIntervalIsDeferredToItsEndNotDropped() {
        val gate = PromptRedialGate(1_000L)
        gate.request(10_000L); gate.ran(10_000L)
        assertEquals(700L, gate.request(10_300L))
        gate.ran(11_000L)
        assertEquals(0L, gate.request(12_000L))
        gate.ran(12_000L)
        assertEquals(0L, gate.request(15_000L))
    }

    @Test fun anAbandonedPostLetsTheNextTriggerScheduleAgain() {
        val gate = PromptRedialGate(1_000L)
        assertEquals(0L, gate.request(1_000L))
        gate.abandoned()
        assertEquals(0L, gate.request(1_001L))
    }
}

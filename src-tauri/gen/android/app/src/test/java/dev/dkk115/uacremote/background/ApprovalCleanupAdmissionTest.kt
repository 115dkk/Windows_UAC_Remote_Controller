// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ApprovalCleanupAdmissionTest {
    @Test fun retirementAdmissionWaitIsBoundedWithoutAFailureBudget() {
        val admission = ApprovalCleanupAdmission()
        val delays = mutableListOf<Long>()
        repeat(12) { delays += admission.defer() }

        assertEquals(listOf(50L, 100L, 200L, 400L, 800L, 1000L), delays.take(6))
        assertTrue(delays.all { it in 50L..1000L })
        assertEquals(12, admission.waits())
    }
}

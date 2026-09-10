// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import android.content.Intent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure formatting/category tests. No Log call, boot or service execution. */
class BootDiagnosticsTest {
    @Test fun onlyFixedAcceptedBootActionCategoriesCanReachTheRecord() {
        assertEquals(BootDiagnosticAction.LOCKED_BOOT, BootDiagnostics.bootAction(Intent.ACTION_LOCKED_BOOT_COMPLETED))
        assertEquals(BootDiagnosticAction.BOOT, BootDiagnostics.bootAction(Intent.ACTION_BOOT_COMPLETED))
        assertEquals(BootDiagnosticAction.PACKAGE_REPLACED, BootDiagnostics.bootAction(Intent.ACTION_MY_PACKAGE_REPLACED))
        for (untrusted in listOf(null, "", "synthetic-untrusted-action", Intent.ACTION_USER_UNLOCKED)) {
            assertNull(BootDiagnostics.bootAction(untrusted))
        }
    }

    @Test fun everyStageHasBoundedClosedAlphabetMetadataEvenWithAllFieldsPresent() {
        for (stage in BootDiagnosticStage.values()) {
            val line = BootDiagnosticRecord(stage,
                action = BootDiagnosticAction.values().maxByOrNull { it.name.length },
                component = BootComponentState.values().maxByOrNull { it.name.length },
                unlock = UserUnlockObservation.values().maxByOrNull { it.name.length },
                result = ServiceControlResult.values().maxByOrNull { it.name.length },
                failure = BootDiagnosticFailure.values().maxByOrNull { it.name.length },
                admitted = false, sticky = false, generationPresent = false,
                attached = false, promoted = false, keptCurrent = false,
                activation = BootActivationState.values().maxByOrNull { it.name.length },
                activationPending = false, activationUncertain = false).line()
            assertTrue(line.length <= BootDiagnostics.MAX_LINE_CHARS)
            assertTrue(line.matches(Regex("[A-Za-z_= ]+")))
            assertFalse(line.contains('\n'))
            assertFalse(line.contains('\r'))
        }
        assertEquals("stage=APPLICATION_CREATE", BootDiagnosticRecord(BootDiagnosticStage.APPLICATION_CREATE).line())
    }

    @Test fun exceptionMessagesAndClassesAreNotRendered() {
        val syntheticMessage = "synthetic-private-body /synthetic/path extra=untrusted"
        val security = BootDiagnostics.failureCategory(SecurityException(syntheticMessage))
        val other = BootDiagnostics.failureCategory(IllegalStateException(syntheticMessage))
        assertEquals(BootDiagnosticFailure.SECURITY, security)
        assertEquals(BootDiagnosticFailure.OTHER, other)
        for (category in listOf(security, other)) {
            val line = BootDiagnosticRecord(BootDiagnosticStage.START_REQUEST_FAILED, failure = category).line()
            assertFalse(line.contains(syntheticMessage))
            assertFalse(line.contains("Exception"))
            assertFalse(line.contains("synthetic"))
        }
    }

    @Test fun staleStartObservationDoesNotDescribeTheRejectedGenerationAsAdmitted() {
        assertEquals("stage=GENERATION_REJECTED admitted=false generation_present=true kept_current=true",
            BootDiagnosticRecord(BootDiagnosticStage.GENERATION_REJECTED,
                admitted = false, generationPresent = true, keptCurrent = true).line())
    }
}

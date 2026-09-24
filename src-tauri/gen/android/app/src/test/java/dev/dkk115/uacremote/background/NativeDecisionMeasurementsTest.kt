// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.background

import dev.dkk115.uacremote.AndroidDiagnosticStore
import dev.dkk115.uacremote.nativecore.NativeOutcomeKind
import dev.dkk115.uacremote.nativecore.NativeOutcomeReceipt
import org.junit.Assert.*
import org.junit.Test

/** Synthetic correlation arithmetic only, not Android/Windows authentication evidence. */
class NativeDecisionMeasurementsTest {
    private val locator = "1".repeat(32)
    private fun ids(seed: Int) = (0..6).map { ByteArray(32) { (seed + it).toByte() } }
    private fun receipt(id: ByteArray, at: ULong, kind: NativeOutcomeKind = NativeOutcomeKind.APPROVED) =
        NativeOutcomeReceipt(id, kind, at)

    @Test fun onlyExactReceiptCompletesOnceAndDurationsExcludeHumanTime() {
        val lines = ArrayList<String>()
        val metric = NativeDecisionMeasurements { lines.add(it) }
        val expected = ids(1)
        val observation = metric.accepted(locator, NativeRequestAction.APPROVE, expected, 1_000_000_000)
        metric.prepared(locator, observation, 2_000_000_000, 2_050_000_000)
        assertFalse(metric.observe(listOf(receipt(ids(20)[0], 2_300_000_000u))))
        assertTrue(metric.observe(listOf(receipt(expected[0], 2_300_000_000u))))
        assertFalse(metric.observe(listOf(receipt(expected[0], 2_800_000_000u))))
        assertEquals(1, lines.size)
        assertTrue(lines.single().contains("action_to_receipt_ms=1300 action_to_auth_ms=1000 auth_to_receipt_ms=300 local_ready_to_receipt_ms=250"))
        assertTrue(AndroidDiagnosticStore.persistable("UacNative", lines.single()))
        assertFalse(lines.single().contains(locator))
    }

    @Test fun expiredOrBackwardsSamplesCannotProduceLatencyAndDiagnosticFailureIsHarmless() {
        val metric = NativeDecisionMeasurements { throw IllegalStateException("synthetic diagnostic failure") }
        val expected = ids(1)
        metric.accepted(locator, NativeRequestAction.DENY, expected, 1_000)
        assertFalse(metric.observe(listOf(receipt(expected[1], 999u, NativeOutcomeKind.DENIED))))
        assertFalse(metric.observe(listOf(receipt(expected[1], 300_000_001_001u, NativeOutcomeKind.DENIED))))
        assertTrue(metric.observe(listOf(receipt(expected[1], 2_000u, NativeOutcomeKind.DENIED))))
        assertFalse(metric.observe(listOf(receipt(expected[1], 3_000u, NativeOutcomeKind.DENIED))))
    }

    @Test fun boundedDiagnosticRejectsUnknownFieldsAndImpossibleDurations() {
        val line = "UAC_NATIVE_DECISION_V1 sample=1 action=approve outcome=approved timing_eligible=true action_to_receipt_ms=500 action_to_auth_ms=200 auth_to_receipt_ms=300 local_ready_to_receipt_ms=250"
        assertTrue(AndroidDiagnosticStore.persistable("UacNative", line))
        for (invalid in listOf(line + " request=secret", line.replace("sample=1", "sample=1000001"),
            line.replace("auth_to_receipt_ms=300", "auth_to_receipt_ms=301"),
            line.replace("timing_eligible=true", "timing_eligible=false"),
            line.replace("action=approve", "action=deny"), line.replace("outcome=approved", "outcome=socket_written"))) {
            assertFalse(AndroidDiagnosticStore.persistable("UacNative", invalid))
        }
    }

    @Test fun localCancellationIsNotPcCancellationAndExactPcReceiptCanSupersedeIt() {
        val lines = ArrayList<String>()
        val metric = NativeDecisionMeasurements { lines.add(it) }
        val expected = ids(1)
        val observation = metric.accepted(locator, NativeRequestAction.APPROVE, expected, 1_000)
        assertEquals("authenticating", metric.feedbackPhase(locator))
        metric.localStatus(locator, observation, true, 2_000)
        metric.progress(locator, observation, NativeRequestPhase.PENDING, 3_000)
        assertEquals("authentication_cancelled", metric.feedbackPhase(locator))
        assertTrue(lines.isEmpty()) // No PC result is fabricated by cancellation.
        assertTrue(metric.observe(listOf(receipt(expected[3], 4_000uL, NativeOutcomeKind.CANCELLED))))
        assertEquals("cancelled", metric.feedbackPhase(locator))
        assertEquals(1, lines.size)
    }

    @Test fun pipelineWaitBeginsOnlyAfterNativeDeliveryAndUnconfirmedIsSupersedable() {
        val metric = NativeDecisionMeasurements { }
        val expected = ids(1)
        val observation = metric.accepted(locator, NativeRequestAction.APPROVE, expected, 1_000)
        metric.prepared(locator, observation, 2_000, 3_000)
        metric.progress(locator, observation, NativeRequestPhase.WAITING, 3_000)
        assertEquals("preparing", metric.feedbackPhase(locator))
        metric.progress(locator, observation, NativeRequestPhase.SENDING, 4_000)
        assertEquals("sending", metric.feedbackPhase(locator))
        metric.progress(locator, observation, NativeRequestPhase.AWAITING_OUTCOME, 5_000)
        assertEquals("awaiting_pc", metric.feedbackPhase(locator))
        metric.progress(locator, observation, NativeRequestPhase.UNAVAILABLE, 6_000)
        assertEquals("local_unconfirmed", metric.feedbackPhase(locator))
        metric.progress(locator, observation, NativeRequestPhase.AWAITING_OUTCOME, 7_000)
        assertEquals("local_unconfirmed", metric.feedbackPhase(locator))
        assertTrue(metric.observe(listOf(receipt(expected[0], 8_000uL))))
        assertEquals("approved", metric.feedbackPhase(locator))
    }

    @Test fun cancelledAttemptCanBeRetriedWithoutInheritingOldStart() {
        val metric = NativeDecisionMeasurements { }
        val original = metric.accepted(locator, NativeRequestAction.APPROVE, ids(1), 1_000)
        metric.localStatus(locator, original, true, 2_000)
        metric.accepted(locator, NativeRequestAction.APPROVE, ids(1), 3_000)
        assertEquals("authenticating", metric.feedbackPhase(locator))
        assertFalse(metric.observe(listOf(receipt(ids(1)[0], 2_500uL))))
    }

    @Test fun oldApprovalCallbacksCannotAlterNewDenialAndSharedIdsExcludeTiming() {
        val lines = ArrayList<String>()
        val metric = NativeDecisionMeasurements { lines.add(it) }
        val original = metric.accepted(locator, NativeRequestAction.APPROVE, ids(1), 1_000)
        val latest = metric.accepted(locator, NativeRequestAction.DENY, ids(1), 2_000)
        metric.localStatus(locator, original, true, 3_000)
        metric.prepared(locator, original, 3_000, 4_000)
        metric.progress(locator, original, NativeRequestPhase.PENDING, 5_000)
        assertEquals("preparing", metric.feedbackPhase(locator))
        metric.prepared(locator, latest, null, 6_000)
        metric.progress(locator, latest, NativeRequestPhase.AWAITING_OUTCOME, 7_000)
        assertTrue(metric.observe(listOf(receipt(ids(1)[1], 8_000uL, NativeOutcomeKind.DENIED))))
        assertEquals("denied", metric.feedbackPhase(locator))
        assertFalse(metric.timingAvailable(locator))
        assertTrue(lines.single().contains("timing_eligible=false"))
        assertTrue(lines.single().contains("auth_to_receipt_ms=none"))
    }

    @Test fun retryAndDifferentLocatorOverlapStayAmbiguousButUnrelatedRequestIsMeasured() {
        val metric = NativeDecisionMeasurements { }
        val first = metric.accepted(locator, NativeRequestAction.APPROVE, ids(1), 1_000)
        metric.localStatus(locator, first, true, 2_000)
        val retry = metric.accepted(locator, NativeRequestAction.APPROVE, ids(1), 3_000)
        metric.progress(locator, first, NativeRequestPhase.UNAVAILABLE, 4_000)
        assertEquals("authenticating", metric.feedbackPhase(locator))
        metric.prepared(locator, retry, 4_000, 5_000)
        val otherLocator = "2".repeat(32)
        metric.accepted(otherLocator, NativeRequestAction.APPROVE, ids(1), 5_000)
        metric.observe(listOf(receipt(ids(1)[0], 6_000uL)))
        assertEquals("approved", metric.feedbackPhase(locator))
        assertFalse(metric.timingAvailable(locator))
        assertFalse(metric.timingAvailable(otherLocator))
        val uniqueLocator = "3".repeat(32)
        val unique = metric.accepted(uniqueLocator, NativeRequestAction.APPROVE, ids(30), 7_000)
        metric.prepared(uniqueLocator, unique, 8_000, 9_000)
        metric.observe(listOf(receipt(ids(30)[0], 10_000uL)))
        assertTrue(metric.timingAvailable(uniqueLocator))
    }

    @Test fun evictingHistoryCannotMakeAnEligibleOldAttemptLookUnique() {
        val metric = NativeDecisionMeasurements { }
        repeat(65) { index -> metric.accepted(locator, NativeRequestAction.APPROVE, ids(index + 1), index.toLong() + 1) }
        val latest = metric.accepted(locator, NativeRequestAction.APPROVE, ids(1), 100)
        metric.prepared(locator, latest, 110, 120)
        metric.observe(listOf(receipt(ids(1)[0], 130uL)))
        assertEquals("approved", metric.feedbackPhase(locator))
        assertFalse(metric.timingAvailable(locator))
        val later = metric.accepted(locator, NativeRequestAction.APPROVE, ids(100), 300_000_001_000)
        metric.prepared(locator, later, 300_000_002_000, 300_000_003_000)
        metric.observe(listOf(receipt(ids(100)[0], 300_000_004_000uL)))
        assertTrue(metric.timingAvailable(locator))
    }

    @Test fun missingAuthOrOppositeOutcomeCannotBecomeAuthenticationLatency() {
        val lines = ArrayList<String>()
        val metric = NativeDecisionMeasurements { lines.add(it) }
        metric.accepted(locator, NativeRequestAction.APPROVE, ids(1), 1_000)
        metric.observe(listOf(receipt(ids(1)[0], 2_000uL)))
        assertFalse(metric.timingAvailable(locator))
        val other = "2".repeat(32)
        val token = metric.accepted(other, NativeRequestAction.APPROVE, ids(20), 3_000)
        metric.prepared(other, token, 4_000, 5_000)
        metric.observe(listOf(receipt(ids(20)[1], 6_000uL, NativeOutcomeKind.DENIED)))
        assertEquals("denied", metric.feedbackPhase(other))
        assertFalse(metric.timingAvailable(other))
        assertTrue(lines.all { it.contains("auth_to_receipt_ms=none") })
    }
}

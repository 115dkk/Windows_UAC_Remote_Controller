// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Fixed synthetic framing/lifetime only. No Android key, provider or native ABI call. */
class DenialSigningPolicyTest {
    private fun statement(): ByteArray {
        val prefix = "Windows-UAC-Remote-Controller/deny/v1\u0000".toByteArray(Charsets.US_ASCII)
        return prefix + ByteArray(199).also { it[1] = 1; it[18] = 2 }
    }
    @Test fun denialDomainVersionAndPurposeAreExact() {
        val bytes = statement()
        assertEquals(237, bytes.size)
        assertEquals(bytes.size, DenialSigningPolicy.statementBytes)
        assertTrue(DenialSigningPolicy.validStatement(bytes))
        for (index in 0 until 38) {
            val changed = bytes.copyOf(); changed[index] = (changed[index].toInt() xor 1).toByte()
            assertFalse(DenialSigningPolicy.validStatement(changed))
        }
        for (index in listOf(38, 39, 56)) {
            val changed = bytes.copyOf(); changed[index] = (changed[index].toInt() xor 1).toByte()
            assertFalse(DenialSigningPolicy.validStatement(changed))
        }
    }
    @Test fun approvalTlsPrehashTruncationAndExtensionsAreRejected() {
        assertFalse(DenialSigningPolicy.validStatement("Windows-UAC-Remote-Controller/approve/v1\u0000".toByteArray() + ByteArray(199)))
        assertFalse(DenialSigningPolicy.validStatement("TLS 1.3, client CertificateVerify".toByteArray()))
        for (size in listOf(0, 32, 48, 236, 238, 4096)) assertFalse(DenialSigningPolicy.validStatement(statement().copyOf(size)))
    }
    @Test fun derBoundDoesNotImposeALowSFilter() {
        for (length in 8..72) assertTrue(DenialSigningPolicy.validDerLength(length))
        for (length in listOf(-1, 0, 7, 73, 4096)) assertFalse(DenialSigningPolicy.validDerLength(length))
        // Strict DER/key verification belongs to Rust, not this size-only helper.
    }
    @Test fun timeCannotRegressOrReachOriginalDeadline() {
        val time = DenialTimeWindow(100, 10)
        assertNull(time.observe(10)); assertNull(time.observe(99))
        assertEquals(DenialSigningError.CLOCK_REGRESSED, time.observe(98))
        assertEquals(DenialSigningError.EXPIRED, time.observe(100))
        assertEquals(DenialSigningError.CLOCK_UNAVAILABLE, time.observe(-1))
        assertEquals(DenialSigningError.INVALID_INPUT, DenialTimeWindow(0, 0).observe(0))
    }
    @Test fun cancellationDoesNotPretendAnInFlightProviderReturned() {
        val state = DenialOperationPolicy()
        assertEquals(DenialOperationObservation.NOT_STARTED, state.observation())
        assertTrue(state.begin()); assertFalse(state.begin())
        state.cancel()
        assertFalse(state.mayReturn()); assertFalse(state.mayClean())
        assertEquals(DenialOperationObservation.RUNNING, state.observation())
        state.returned(); assertTrue(state.mayClean())
        state.cleaned(); assertEquals(DenialOperationObservation.QUIESCENT, state.observation())
        assertFalse(state.begin())
    }
    @Test fun trackedZeroProviderOperationMayBecomeQuiescent() {
        val beforeStart = DenialOperationPolicy()
        beforeStart.cancel(); assertFalse(beforeStart.begin())
        beforeStart.cleaned(); assertEquals(DenialOperationObservation.QUIESCENT, beforeStart.observation())
        val rejectedAfterClaimBeforeProvider = DenialOperationPolicy()
        assertTrue(rejectedAfterClaimBeforeProvider.begin())
        rejectedAfterClaimBeforeProvider.cancel(); rejectedAfterClaimBeforeProvider.returned()
        rejectedAfterClaimBeforeProvider.cleaned()
        assertEquals(DenialOperationObservation.QUIESCENT, rejectedAfterClaimBeforeProvider.observation())
    }
    @Test fun cleanupFailureRequiresExplicitResumeAndCleanedStateDoesNotRegressOnCancel() {
        val state = DenialOperationPolicy()
        state.cancel(); state.cleanupFailed()
        assertEquals(DenialOperationObservation.FAILED, state.observation())
        var rejected = false
        try { state.cleaned() } catch (_: IllegalStateException) { rejected = true }
        assertTrue(rejected)
        state.retryCleanup(); state.cleaned(); state.cancel()
        assertEquals(DenialOperationObservation.QUIESCENT, state.observation())
    }
}

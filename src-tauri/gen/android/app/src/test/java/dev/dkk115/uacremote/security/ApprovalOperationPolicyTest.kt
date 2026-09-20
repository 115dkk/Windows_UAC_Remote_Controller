// SPDX-License-Identifier: GPL-2.0-or-later
package dev.dkk115.uacremote.security

import android.hardware.biometrics.BiometricManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Synthetic identity/state/framing tests ONLY. Never constructs an Activity,
 * Signature, CryptoObject, NativeApprovalPlan, AndroidKeyStore or auth prompt.
 */
class ApprovalOperationPolicyTest {
    private fun policy(signature: Any, deadline: Long = 100): ApprovalOperationPolicy =
        ApprovalOperationPolicy(deadline, 10, signature)

    @Test fun neitherPreparationNorPresentationAlonePermitsSigning() {
        val signature = Any()
        val host = Any()
        val state = policy(signature)
        assertTrue(state.isPrepared())
        assertFalse(state.isAwaitingSigning())
        assertEquals(ApprovalOperationError.ALREADY_USED, state.beginSigning(11))
        assertEquals(ApprovalOperationError.ALREADY_USED, state.authenticated(host, signature, 11))
        assertNull(state.present(host, 12))
        assertFalse(state.isPrepared())
        assertEquals(ApprovalOperationError.ALREADY_USED, state.beginSigning(13))
        assertNull(state.presentationCheck(14))
        assertNull(state.authenticated(host, signature, 15))
        assertTrue(state.isAwaitingSigning())
        assertNull(state.beginSigning(16))
        assertFalse(state.isAwaitingSigning())
    }

    @Test fun onlyExactReturnedSignatureAndPresentingHostCanAdvanceOnce() {
        val signature = Any()
        val host = Any()
        val state = policy(signature)
        assertNull(state.present(host, 11))
        assertTrue(state.isAwaitingAuthentication())
        assertNull(state.authenticated(host, signature, 12))
        assertFalse(state.isAwaitingAuthentication())
        assertEquals(ApprovalOperationError.ALREADY_USED, state.authenticated(host, signature, 13))
        assertNull(state.beginSigning(14))
        assertFalse(state.isQuiescent())
        assertNull(state.signingCheck(15))
        assertNull(state.finishSigning(16))
        assertTrue(state.isQuiescent())
        assertEquals(ApprovalOperationError.ALREADY_USED, state.beginSigning(17))
        assertEquals(ApprovalOperationError.ALREADY_USED, state.present(host, 18))
    }

    private class EqualButDifferent {
        override fun equals(other: Any?): Boolean = other is EqualButDifferent
        override fun hashCode(): Int = 1
    }

    @Test fun nullAnotherOrEqualsOnlySignatureFailsWithoutAuthentication() {
        for (returned in listOf(null, Any(), EqualButDifferent())) {
            val signature = EqualButDifferent()
            val host = Any()
            val state = policy(signature)
            assertNull(state.present(host, 11))
            assertEquals(ApprovalOperationError.CRYPTO_OBJECT_MISMATCH, state.authenticated(host, returned, 12))
            assertTrue(state.isQuiescent())
            assertEquals(ApprovalOperationError.CRYPTO_OBJECT_MISMATCH, state.beginSigning(13))
        }
    }

    @Test fun activityRecreationCannotTakeOverAnOldSignature() {
        val signature = Any()
        val oldHost = Any()
        val replacementHost = Any()
        val state = policy(signature)
        assertNull(state.present(oldHost, 11))
        assertEquals(ApprovalOperationError.ALREADY_USED, state.present(replacementHost, 12))
        assertEquals(ApprovalOperationError.HOST_CHANGED, state.authenticated(replacementHost, signature, 13))
        assertEquals(ApprovalOperationError.HOST_CHANGED, state.authenticated(oldHost, signature, 14))
        assertEquals(ApprovalOperationError.HOST_CHANGED, state.beginSigning(15))
    }

    @Test fun duplicatePresentationDoesNotReplaceTheOriginalHostOrDeadline() {
        val signature = Any()
        val host = Any()
        val state = policy(signature)
        assertNull(state.present(host, 11))
        assertEquals(ApprovalOperationError.ALREADY_USED, state.present(Any(), 12))
        assertNull(state.authenticated(host, signature, 99))
        assertEquals(ApprovalOperationError.EXPIRED, state.beginSigning(100))
        assertTrue(state.isQuiescent())
    }

    @Test fun cancelBeforeOrAfterAuthenticationNeverCreatesASigningPermit() {
        for (authenticate in listOf(false, true)) {
            val signature = Any()
            val host = Any()
            val state = policy(signature)
            assertNull(state.present(host, 11))
            if (authenticate) assertNull(state.authenticated(host, signature, 12))
            assertEquals(ApprovalOperationError.CANCELLED, state.cancel())
            assertTrue(state.isQuiescent())
            assertEquals(ApprovalOperationError.CANCELLED, state.authenticated(host, signature, 13))
            assertEquals(ApprovalOperationError.CANCELLED, state.beginSigning(14))
            assertEquals(ApprovalOperationError.CANCELLED, state.cancel(ApprovalOperationError.AUTHENTICATION_ERROR))
        }
    }

    @Test fun cancelDuringNativeSignKeepsTheSlotBusyUntilTheRealExit() {
        val signature = Any()
        val host = Any()
        val state = policy(signature)
        state.present(host, 11)
        state.authenticated(host, signature, 12)
        assertNull(state.beginSigning(13))
        assertEquals(ApprovalOperationError.ALREADY_USED, state.beginSigning(14))
        assertEquals(ApprovalOperationError.CANCELLED, state.cancel())
        assertFalse(state.isQuiescent())
        assertEquals(ApprovalOperationError.CANCELLED, state.signingCheck(15))
        assertEquals(ApprovalOperationError.CANCELLED, state.finishSigning(16))
        assertTrue(state.isQuiescent())
        assertEquals(ApprovalOperationError.CANCELLED, state.beginSigning(17))
    }

    @Test fun nativeExceptionExitIsTerminalAndCannotLeaveAnAuthenticatedReusableOperation() {
        val signature = Any()
        val host = Any()
        val state = policy(signature)
        state.present(host, 11)
        state.authenticated(host, signature, 12)
        state.beginSigning(13)
        state.signingExited()
        assertTrue(state.isQuiescent())
        assertEquals(ApprovalOperationError.SIGNING_FAILED, state.beginSigning(14))
        assertEquals(ApprovalOperationError.SIGNING_FAILED, state.terminalError())
    }

    @Test fun deadlineEqualityAfterBlockingSignRejectsItsResult() {
        val signature = Any()
        val host = Any()
        val state = policy(signature)
        state.present(host, 11)
        state.authenticated(host, signature, 12)
        state.beginSigning(13)
        assertEquals(ApprovalOperationError.EXPIRED, state.finishSigning(100))
        assertTrue(state.isQuiescent())
        assertEquals(ApprovalOperationError.EXPIRED, state.beginSigning(101))
    }

    @Test fun nativeClockRegressionAndNegativeReadFailClosed() {
        for ((time, expected) in listOf(9L to ApprovalOperationError.CLOCK_REGRESSED,
            -1L to ApprovalOperationError.CLOCK_UNAVAILABLE, 100L to ApprovalOperationError.EXPIRED)) {
            val state = policy(Any())
            assertEquals(expected, state.present(Any(), time))
            assertTrue(state.isQuiescent())
            assertEquals(expected, state.beginSigning(20))
        }
        val signature = Any()
        val host = Any()
        val state = policy(signature)
        state.present(host, 20)
        assertEquals(ApprovalOperationError.CLOCK_REGRESSED, state.authenticated(host, signature, 19))
    }

    @Test fun invalidInitialLifetimesCannotConstructPolicy() {
        for ((started, deadline) in listOf(-1L to 100L, 10L to 10L, 11L to 10L)) {
            var rejected = false
            try { ApprovalOperationPolicy(deadline, started, Any()) }
            catch (_: IllegalArgumentException) { rejected = true }
            assertTrue(rejected)
        }
        assertNull(ApprovalOperationPolicy(Long.MAX_VALUE, 0, Any()).present(Any(), 0))
    }

    @Test fun credentialOnlyAvailabilityUsesOneStrongOrCredentialQueryNotTwoRequirements() {
        val expected = BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        assertEquals(expected, ApprovalOperationBounds.ALLOWED_AUTHENTICATORS)
        assertEquals(BiometricManager.Authenticators.DEVICE_CREDENTIAL,
            expected and BiometricManager.Authenticators.DEVICE_CREDENTIAL)
        // SUCCESS of that combined query is sufficient; no separate sensor or
        // biometric-enrollment observation exists in this contract.
        assertTrue(ApprovalOperationBounds.authenticationAvailable(BiometricManager.BIOMETRIC_SUCCESS))
        for (unavailable in listOf(null, -1, 1, 11, 12, 15)) {
            assertFalse(ApprovalOperationBounds.authenticationAvailable(unavailable))
        }
    }

    private fun syntheticApproveFraming(): ByteArray {
        val prefix = "Windows-UAC-Remote-Controller/approve/v1\u0000".toByteArray(Charsets.US_ASCII)
        return ByteArray(prefix.size + 2 + 16 + 1 + 180).also {
            prefix.copyInto(it)
            it[prefix.size + 1] = 1
            it[prefix.size + 2 + 16] = 1
        }
    }

    @Test fun onlyBoundedCanonicalApproveFramingIsAdmittedNoDenyOrPrehash() {
        val framed = syntheticApproveFraming()
        assertEquals(ApprovalOperationBounds.signingBytes, framed.size)
        assertTrue(ApprovalOperationBounds.validSigningBytes(framed))
        for (changed in listOf(ByteArray(0), ByteArray(32), framed.copyOf(framed.size - 1), framed + byteArrayOf(0),
            framed.copyOf().also { it[0] = 0 },
            framed.copyOf().also { it[it.size - 180 - 1] = 2 },
            framed.copyOf().also { it[it.size - 180 - 1 - 16 - 1] = 2 })) {
            assertFalse(ApprovalOperationBounds.validSigningBytes(changed))
        }
    }

    @Test fun derBoundDoesNotImposeLowSOrClaimCryptographicVerification() {
        for (length in 8..72) assertTrue(ApprovalOperationBounds.validDerLength(length))
        for (length in listOf(-1, 0, 7, 73, Int.MAX_VALUE)) assertFalse(ApprovalOperationBounds.validDerLength(length))
        // This function checks size only. Rust's strict DER/P-256 verifier owns
        // actual cryptographic verification and accepts both valid S values.
        assertEquals("ApprovalOperationPolicy([redacted])", policy(Any()).toString())
        assertEquals("ApprovalOperationOutcome.Value([redacted])", ApprovalOperationOutcome.Value(byteArrayOf(1, 2, 3)).toString())
    }
}
